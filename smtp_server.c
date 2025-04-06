#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <libpq-fe.h>
#include <crypt.h>

#define PORT 2525
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define DATA_BUFFER_SIZE 4096

// PostgreSQL connection
PGconn *conn;

// OpenSSL context functions
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
void *handle_client(void *arg);
void start_tls(SSL *ssl, int client_socket);

// Authentication
int authenticate_user(const char *username, const char *password);

// Email handling functions
void parse_email_content(const char *input, char *subject, char *body);
void store_email(const char *sender, const char *recipient, const char *email_data);

int main()
{
  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_len = sizeof(client_addr);
  pthread_t thread_id;

  // Initialize OpenSSL
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = create_ssl_context();
  configure_ssl_context(ctx);

  // Initialize PostgreSQL
  conn = PQconnectdb("dbname=smtp_server user=myuser password=mypassword");
  if (PQstatus(conn) != CONNECTION_OK)
  {
    fprintf(stderr, "PostgreSQL Connection Error: %s\n", PQerrorMessage(conn));
    exit(1);
  }

  // Create server socket
  if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("Socket failed");
    exit(1);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
  {
    perror("Bind failed");
    exit(1);
  }

  if (listen(server_socket, MAX_CLIENTS) == -1)
  {
    perror("Listen failed");
    exit(1);
  }

  printf("SMTP Server running on port %d...\n", PORT);

  while (1)
  {
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0)
    {
      perror("Accept failed");
      continue;
    }

    int *client_ptr = malloc(sizeof(int));
    *client_ptr = client_socket;

    pthread_create(&thread_id, NULL, handle_client, client_ptr);
    pthread_detach(thread_id); // Clean up automatically
  }

  close(server_socket);
  SSL_CTX_free(ctx);
  PQfinish(conn);

  return 0;
}

SSL_CTX *create_ssl_context()
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx)
  {
    perror("Unable to create SSL context");
    exit(1);
  }
  return ctx;
}

void configure_ssl_context(SSL_CTX *ctx)
{
  SSL_CTX_use_certificate_file(ctx, "smtp_cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "smtp_key.pem", SSL_FILETYPE_PEM);
}

void *handle_client(void *arg)
{
  int client_socket = *(int *)arg;
  free(arg);
  SSL *ssl = NULL;

  char buffer[BUFFER_SIZE];
  char sender[100] = {0}, receiver[100] = {0};
  char email_data[DATA_BUFFER_SIZE] = {0};
  int authenticated = 0;
  char username[50] = {0}, password[50] = {0};

  send(client_socket, "220 Simple SMTP Server\n", 23, 0);

  while (1)
  {
    memset(buffer, 0, BUFFER_SIZE);
    if (recv(client_socket, buffer, BUFFER_SIZE, 0) <= 0)
      break;
    printf("Client: %s", buffer);

    if (strncmp(buffer, "EHLO", 4) == 0)
    {
      send(client_socket, "250-Hello\n250-STARTTLS\n", 24, 0);
    }
    else if (strncmp(buffer, "STARTTLS", 8) == 0)
    {
      send(client_socket, "220 Ready to start TLS\n", 23, 0);

      ssl = SSL_new(create_ssl_context());
      SSL_set_fd(ssl, client_socket);
      start_tls(ssl, client_socket);
      return NULL;
    }
    else if (strncmp(buffer, "AUTH LOGIN", 10) == 0)
    {
      send(client_socket, "334 Username:\n", 14, 0);
      recv(client_socket, username, 50, 0);
      send(client_socket, "334 Password:\n", 14, 0);
      recv(client_socket, password, 50, 0);

      if (authenticate_user(username, password))
      {
        authenticated = 1;
        send(client_socket, "235 Authentication successful\n", 30, 0);
      }
      else
      {
        send(client_socket, "535 Authentication failed\n", 26, 0);
        close(client_socket);
        return NULL;
      }
    }
    else if (strncmp(buffer, "MAIL FROM:", 10) == 0)
    {
      sscanf(buffer, "MAIL FROM: <%99[^>]>", sender);
      printf("Debug: Parsed MAIL FROM: '%s'\n", sender);
      send(client_socket, "250 OK\n", 7, 0);
    }
    else if (strncmp(buffer, "RCPT TO:", 8) == 0)
    {
      sscanf(buffer, "RCPT TO: <%99[^>]>", receiver);
      printf("Debug: Parsed RCPT TO: '%s'\n", receiver);
      send(client_socket, "250 OK\n", 7, 0);
    }
    else if (strncmp(buffer, "DATA", 4) == 0)
    {
      send(client_socket, "354 End data with <CR><LF>.<CR><LF>\n", 36, 0);
      memset(email_data, 0, sizeof(email_data));
      int total_bytes = 0;
      while (1)
      {
        int bytes = recv(client_socket, email_data + total_bytes, sizeof(email_data) - total_bytes - 1, 0);
        if (bytes <= 0)
          break;
        total_bytes += bytes;
        email_data[total_bytes] = '\0';
        if (strstr(email_data, "\r\n.\r\n") != NULL)
          break;
      }
      store_email(sender, receiver, email_data);
      send(client_socket, "250 OK\n", 7, 0);
    }
    else if (strncmp(buffer, "QUIT", 4) == 0)
    {
      send(client_socket, "221 Bye\n", 8, 0);
      break;
    }
  }

  if (ssl)
  {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  close(client_socket);
  return NULL;
}

void start_tls(SSL *ssl, int client_socket)
{
  if (SSL_accept(ssl) <= 0)
  {
    ERR_print_errors_fp(stderr);
    close(client_socket);
    return;
  }

  send(client_socket, "250 TLS negotiation successful\n", 31, 0);
}

int authenticate_user(const char *username, const char *password)
{
  char query[256];
  snprintf(query, sizeof(query), "SELECT password_hash FROM users WHERE username='%s'", username);
  PGresult *res = PQexec(conn, query);

  if (!res || PQntuples(res) == 0)
  {
    PQclear(res);
    return 0;
  }

  char *stored_hash = PQgetvalue(res, 0, 0);
  int success = strcmp(crypt(password, stored_hash), stored_hash) == 0;
  PQclear(res);
  return success;
}

void parse_email_content(const char *input, char *subject, char *body)
{
  const char *subject_ptr = strstr(input, "Subject:");
  if (subject_ptr)
  {
    subject_ptr += 8;
    while (*subject_ptr == ' ' || *subject_ptr == '\t')
      subject_ptr++;
    const char *subject_end = strchr(subject_ptr, '\r');
    if (subject_end)
    {
      size_t len = subject_end - subject_ptr;
      strncpy(subject, subject_ptr, len >= 256 ? 255 : len);
      subject[len] = '\0';
    }
    else
    {
      strncpy(subject, subject_ptr, 255);
      subject[255] = '\0';
    }
  }
  else
  {
    strcpy(subject, "(No Subject)");
  }

  const char *body_ptr = strstr(input, "\r\n\r\n");
  if (body_ptr)
  {
    body_ptr += 4;
  }
  else
  {
    body_ptr = input;
  }

  const char *end_marker = strstr(body_ptr, "\r\n.\r\n");
  if (end_marker)
  {
    size_t len = end_marker - body_ptr;
    strncpy(body, body_ptr, len >= 2048 ? 2047 : len);
    body[len] = '\0';
  }
  else
  {
    strncpy(body, body_ptr, 2047);
    body[2047] = '\0';
  }

  size_t blen = strlen(body);
  while (blen > 0 && (body[blen - 1] == '\r' || body[blen - 1] == '\n'))
  {
    body[--blen] = '\0';
  }
}

void store_email(const char *sender, const char *recipient, const char *email_data)
{
  char query[4096];
  char subject[256] = {0};
  char body[2048] = {0};

  parse_email_content(email_data, subject, body);

  snprintf(query, sizeof(query),
           "INSERT INTO users (username, password_hash, email) VALUES ('%s', 'some_password', '%s') ON CONFLICT (email) DO NOTHING;",
           sender, sender);
  PGresult *res = PQexec(conn, query);
  PQclear(res);

  snprintf(query, sizeof(query),
           "INSERT INTO users (username, password_hash, email) VALUES ('%s', 'some_password', '%s') ON CONFLICT (email) DO NOTHING;",
           recipient, recipient);
  res = PQexec(conn, query);
  PQclear(res);

  snprintf(query, sizeof(query),
           "INSERT INTO emails (sender, recipient, subject, body) VALUES ('%s', '%s', '%s', '%s');",
           sender, recipient, subject, body);
  res = PQexec(conn, query);
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
  {
    fprintf(stderr, "Failed to store email: %s\n", PQerrorMessage(conn));
  }
  else
  {
    printf("Email stored successfully.\n");
  }
  PQclear(res);
}

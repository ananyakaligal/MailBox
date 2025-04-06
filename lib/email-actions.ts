"use server"
import { createClient } from "@/lib/supabase-server"
import type { Email } from "@/lib/types"
import { requireAuth } from "@/lib/auth-actions"

export async function getEmails() {
  try {
    const userId = await requireAuth()
    const supabase = createClient()

    // Get inbox emails
    const { data: inboxData, error: inboxError } = await supabase
      .from("emails")
      .select(`
        id,
        subject,
        content,
        created_at,
        read,
        from:from_user_id(id, email, username),
        to:to_user_id(id, email, username)
      `)
      .eq("to_user_id", userId)
      .order("created_at", { ascending: false })

    if (inboxError) {
      return { success: false, error: "Failed to fetch inbox emails" }
    }

    // Get sent emails
    const { data: sentData, error: sentError } = await supabase
      .from("emails")
      .select(`
        id,
        subject,
        content,
        created_at,
        read,
        from:from_user_id(id, email, username),
        to:to_user_id(id, email, username)
      `)
      .eq("from_user_id", userId)
      .order("created_at", { ascending: false })

    if (sentError) {
      return { success: false, error: "Failed to fetch sent emails" }
    }

    // Format emails
    const inbox: Email[] = inboxData.map((email: any) => ({
      id: email.id,
      subject: email.subject,
      content: email.content,
      date: email.created_at,
      read: email.read,
      from: {
        id: email.from.id,
        email: email.from.email,
        name: email.from.username,
      },
      to: {
        id: email.to.id,
        email: email.to.email,
        name: email.to.username,
      },
    }))

    const sent: Email[] = sentData.map((email: any) => ({
      id: email.id,
      subject: email.subject,
      content: email.content,
      date: email.created_at,
      read: true, // Sent emails are always read
      from: {
        id: email.from.id,
        email: email.from.email,
        name: email.from.username,
      },
      to: {
        id: email.to.id,
        email: email.to.email,
        name: email.to.username,
      },
    }))

    return { success: true, inbox, sent }
  } catch (error) {
    console.error("Get emails error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function getEmailById(id: string) {
  try {
    const userId = await requireAuth()
    const supabase = createClient()

    // Get email
    const { data: email, error } = await supabase
      .from("emails")
      .select(`
        id,
        subject,
        content,
        created_at,
        read,
        from:from_user_id(id, email, username),
        to:to_user_id(id, email, username)
      `)
      .eq("id", id)
      .or(`from_user_id.eq.${userId},to_user_id.eq.${userId}`)
      .single()

    if (error || !email) {
      return { success: false, error: "Email not found" }
    }

    // Format email
    const formattedEmail: Email = {
      id: email.id,
      subject: email.subject,
      content: email.content,
      date: email.created_at,
      read: email.read,
      from: {
        id: email.from.id,
        email: email.from.email,
        name: email.from.username,
      },
      to: {
        id: email.to.id,
        email: email.to.email,
        name: email.to.username,
      },
    }

    return { success: true, email: formattedEmail }
  } catch (error) {
    console.error("Get email by ID error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function markEmailAsRead(id: string) {
  try {
    const userId = await requireAuth()
    const supabase = createClient()

    // Update email
    const { error } = await supabase.from("emails").update({ read: true }).eq("id", id).eq("to_user_id", userId)

    if (error) {
      return { success: false, error: "Failed to mark email as read" }
    }

    return { success: true }
  } catch (error) {
    console.error("Mark email as read error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function deleteEmail(id: string) {
  try {
    const userId = await requireAuth()
    const supabase = createClient()

    // Delete email
    const { error } = await supabase
      .from("emails")
      .delete()
      .eq("id", id)
      .or(`from_user_id.eq.${userId},to_user_id.eq.${userId}`)

    if (error) {
      return { success: false, error: "Failed to delete email" }
    }

    return { success: true }
  } catch (error) {
    console.error("Delete email error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function sendEmail(data: {
  to: string
  subject: string
  content: string
}) {
  try {
    const userId = await requireAuth()
    const supabase = createClient()

    // Get recipient user
    const { data: recipient, error: recipientError } = await supabase
      .from("users")
      .select("id")
      .eq("email", data.to)
      .single()

    if (recipientError || !recipient) {
      return { success: false, error: "Recipient not found" }
    }

    // Create email
    const { error: createError } = await supabase.from("emails").insert({
      subject: data.subject,
      content: data.content,
      from_user_id: userId,
      to_user_id: recipient.id,
      created_at: new Date().toISOString(),
      read: false,
    })

    if (createError) {
      return { success: false, error: "Failed to send email" }
    }

    return { success: true }
  } catch (error) {
    console.error("Send email error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}


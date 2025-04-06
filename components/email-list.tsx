import Link from "next/link"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { Email } from "@/lib/types"
import { formatDate } from "@/lib/utils"

interface EmailListProps {
  emails: Email[]
  type: "inbox" | "sent"
}

export function EmailList({ emails, type }: EmailListProps) {
  return (
    <div className="space-y-4">
      {emails.map((email) => (
        <Link href={`/dashboard/email/${email.id}`} key={email.id}>
          <Card
            className={`cursor-pointer transition-colors hover:bg-accent/50 ${!email.read && type === "inbox" ? "border-primary" : ""}`}
          >
            <CardContent className="p-4">
              <div className="flex flex-col space-y-2">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <h3 className={`text-base font-medium ${!email.read && type === "inbox" ? "font-semibold" : ""}`}>
                        {type === "inbox" ? email.from.name : email.to.name}
                      </h3>
                      {!email.read && type === "inbox" && (
                        <Badge variant="default" className="ml-2">
                          New
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {type === "inbox" ? email.from.email : email.to.email}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">{formatDate(email.date)}</span>
                </div>
                <div>
                  <h4 className={`text-sm ${!email.read && type === "inbox" ? "font-medium" : ""}`}>{email.subject}</h4>
                  <p className="line-clamp-1 text-xs text-muted-foreground">{email.content}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}


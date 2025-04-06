"use client"

import { useState, useEffect } from "react"
import { useSearchParams } from "next/navigation"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { EmailList } from "@/components/email-list"
import { ComposeEmailButton } from "@/components/compose-email-button"
import { getEmails } from "@/lib/email-actions"
import type { Email } from "@/lib/types"
import { Loader2 } from "lucide-react"

export default function DashboardPage() {
  const searchParams = useSearchParams()
  const tabParam = searchParams.get("tab")
  const labelParam = searchParams.get("label")

  const [emails, setEmails] = useState<{
    inbox: Email[]
    sent: Email[]
    starred: Email[]
    drafts: Email[]
    archive: Email[]
    trash: Email[]
  }>({
    inbox: [],
    sent: [],
    starred: [],
    drafts: [],
    archive: [],
    trash: [],
  })
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState(tabParam || "inbox")

  useEffect(() => {
    // Update active tab when URL parameter changes
    if (tabParam) {
      setActiveTab(tabParam)
    } else {
      setActiveTab("inbox")
    }
  }, [tabParam])

  useEffect(() => {
    const fetchEmails = async () => {
      try {
        const result = await getEmails()
        if (result.success) {
          // For now, we'll just use inbox and sent emails
          // In a real app, you'd fetch all folder contents
          setEmails({
            inbox: result.inbox || [],
            sent: result.sent || [],
            starred: [],
            drafts: [],
            archive: [],
            trash: [],
          })
        }
      } catch (error) {
        console.error("Failed to fetch emails:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchEmails()
  }, [])

  // Get the title based on active tab or label
  const getTitle = () => {
    if (labelParam) {
      return labelParam.charAt(0).toUpperCase() + labelParam.slice(1)
    }
    return activeTab.charAt(0).toUpperCase() + activeTab.slice(1)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{getTitle()}</h1>
        <ComposeEmailButton />
      </div>

      <Tabs defaultValue="inbox" value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="inbox">
            Inbox
            {emails.inbox.length > 0 && (
              <span className="ml-2 rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
                {emails.inbox.filter((email) => !email.read).length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="starred">Starred</TabsTrigger>
          <TabsTrigger value="sent">Sent</TabsTrigger>
          <TabsTrigger value="drafts">Drafts</TabsTrigger>
        </TabsList>

        <TabsContent value="inbox" className="mt-4">
          {loading ? (
            <div className="flex h-40 items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : emails.inbox.length > 0 ? (
            <EmailList emails={emails.inbox} type="inbox" />
          ) : (
            <div className="flex h-40 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center">
              <h3 className="text-lg font-medium">Your inbox is empty</h3>
              <p className="text-sm text-muted-foreground">When you receive emails, they will appear here.</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="starred" className="mt-4">
          <div className="flex h-40 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center">
            <h3 className="text-lg font-medium">No starred emails</h3>
            <p className="text-sm text-muted-foreground">Star important emails to find them quickly here.</p>
          </div>
        </TabsContent>

        <TabsContent value="sent" className="mt-4">
          {loading ? (
            <div className="flex h-40 items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : emails.sent.length > 0 ? (
            <EmailList emails={emails.sent} type="sent" />
          ) : (
            <div className="flex h-40 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center">
              <h3 className="text-lg font-medium">No sent emails</h3>
              <p className="text-sm text-muted-foreground">When you send emails, they will appear here.</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="drafts" className="mt-4">
          <div className="flex h-40 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center">
            <h3 className="text-lg font-medium">No draft emails</h3>
            <p className="text-sm text-muted-foreground">Saved drafts will appear here.</p>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}


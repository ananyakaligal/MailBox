"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Separator } from "@/components/ui/separator"
import { getEmailById, deleteEmail, markEmailAsRead } from "@/lib/email-actions"
import type { Email } from "@/lib/types"
import { ArrowLeft, Archive, Reply, Trash2, Loader2 } from "lucide-react"
import { formatDate } from "@/lib/utils"
import { ComposeEmailDialog } from "@/components/compose-email-dialog"
import { useToast } from "@/components/ui/use-toast"

export default function EmailViewPage({ params }: { params: { id: string } }) {
  const [email, setEmail] = useState<Email | null>(null)
  const [loading, setLoading] = useState(true)
  const [replyDialogOpen, setReplyDialogOpen] = useState(false)
  const router = useRouter()
  const { toast } = useToast()

  useEffect(() => {
    const fetchEmail = async () => {
      try {
        const result = await getEmailById(params.id)
        if (result.success && result.email) {
          setEmail(result.email)

          // Mark as read if it's not already
          if (!result.email.read) {
            await markEmailAsRead(params.id)
          }
        } else {
          toast({
            title: "Error",
            description: "Email not found",
            variant: "destructive",
          })
          router.push("/dashboard")
        }
      } catch (error) {
        toast({
          title: "Error",
          description: "Failed to load email",
          variant: "destructive",
        })
        router.push("/dashboard")
      } finally {
        setLoading(false)
      }
    }

    fetchEmail()
  }, [params.id, router, toast])

  const handleDelete = async () => {
    try {
      const result = await deleteEmail(params.id)
      if (result.success) {
        toast({
          title: "Success",
          description: "Email deleted successfully",
        })
        router.push("/dashboard")
      } else {
        toast({
          title: "Error",
          description: result.error || "Failed to delete email",
          variant: "destructive",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Something went wrong. Please try again.",
        variant: "destructive",
      })
    }
  }

  const handleArchive = async () => {
    // Implement archive functionality
    toast({
      title: "Info",
      description: "Archive functionality not implemented yet",
    })
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!email) {
    return (
      <div className="flex h-full flex-col items-center justify-center">
        <h2 className="text-xl font-semibold">Email not found</h2>
        <Button variant="link" onClick={() => router.push("/dashboard")} className="mt-2">
          Go back to dashboard
        </Button>
      </div>
    )
  }

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((part) => part[0])
      .join("")
      .toUpperCase()
      .substring(0, 2)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2">
        <Button variant="ghost" size="icon" onClick={() => router.push("/dashboard")}>
          <ArrowLeft className="h-5 w-5" />
          <span className="sr-only">Back</span>
        </Button>
        <h1 className="text-2xl font-bold">View Email</h1>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
          <div className="flex items-start space-x-4">
            <Avatar>
              <AvatarFallback>{getInitials(email.from.name)}</AvatarFallback>
            </Avatar>
            <div>
              <div className="space-y-1">
                <h2 className="text-xl font-semibold leading-none">{email.subject}</h2>
                <div className="flex flex-col space-y-1 text-sm text-muted-foreground sm:flex-row sm:space-x-2 sm:space-y-0">
                  <span>
                    From: {email.from.name} &lt;{email.from.email}&gt;
                  </span>
                  <span>
                    To: {email.to.name} &lt;{email.to.email}&gt;
                  </span>
                  <span>Date: {formatDate(email.date)}</span>
                </div>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <Separator className="mb-4" />
          <div className="prose prose-sm max-w-none dark:prose-invert">
            {email.content.split("\n").map((paragraph, index) => (
              <p key={index}>{paragraph}</p>
            ))}
          </div>
        </CardContent>
        <CardFooter className="flex justify-between">
          <div className="flex space-x-2">
            <Button variant="outline" size="sm" onClick={() => setReplyDialogOpen(true)}>
              <Reply className="mr-2 h-4 w-4" />
              Reply
            </Button>
            <Button variant="outline" size="sm" onClick={handleArchive}>
              <Archive className="mr-2 h-4 w-4" />
              Archive
            </Button>
          </div>
          <Button variant="destructive" size="sm" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </CardFooter>
      </Card>

      <ComposeEmailDialog
        open={replyDialogOpen}
        onOpenChange={setReplyDialogOpen}
        defaultTo={email.from.email}
        defaultSubject={`Re: ${email.subject}`}
        defaultContent={`\n\n-------- Original Message --------\nFrom: ${email.from.name} <${email.from.email}>\nDate: ${formatDate(email.date)}\nSubject: ${email.subject}\n\n${email.content}`}
      />
    </div>
  )
}


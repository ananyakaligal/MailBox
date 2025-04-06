"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Plus } from "lucide-react"
import { ComposeEmailDialog } from "@/components/compose-email-dialog"

export function ComposeEmailButton() {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button onClick={() => setOpen(true)} className="flex items-center">
        <Plus className="mr-2 h-4 w-4" />
        Compose
      </Button>
      <ComposeEmailDialog open={open} onOpenChange={setOpen} />
    </>
  )
}


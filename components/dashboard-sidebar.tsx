"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { ModeToggle } from "@/components/mode-toggle"
import { Sheet, SheetContent } from "@/components/ui/sheet"
import type { User } from "@/lib/types"
import {
  Inbox,
  Send,
  UserIcon,
  LogOut,
  Mail,
  Star,
  Trash2,
  Archive,
  Tag,
  Settings,
  FolderPlus,
  Plus,
  ChevronDown,
  ChevronRight,
} from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"

interface DashboardSidebarProps {
  user: User | null
  onLogout: () => void
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function DashboardSidebar({ user, onLogout, open, onOpenChange }: DashboardSidebarProps) {
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const currentTab = searchParams.get("tab") || "inbox"

  const [foldersOpen, setFoldersOpen] = useState(true)
  const [labelsOpen, setLabelsOpen] = useState(true)

  // Sample data for folders and labels
  const folders = [
    { id: "inbox", name: "Inbox", icon: Inbox, count: 12 },
    { id: "starred", name: "Starred", icon: Star, count: 5 },
    { id: "sent", name: "Sent", icon: Send, count: 0 },
    { id: "drafts", name: "Drafts", icon: Mail, count: 2 },
    { id: "archive", name: "Archive", icon: Archive, count: 0 },
    { id: "trash", name: "Trash", icon: Trash2, count: 0 },
  ]

  const labels = [
    { id: "work", name: "Work", color: "bg-blue-500" },
    { id: "personal", name: "Personal", color: "bg-green-500" },
    { id: "important", name: "Important", color: "bg-red-500" },
    { id: "finance", name: "Finance", color: "bg-yellow-500" },
  ]

  // Storage usage simulation
  const storageUsed = 35 // percentage

  const sidebarContent = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-4 py-6">
        <Mail className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-bold">Secure Mail</h1>
      </div>

      <div className="flex-1 px-4 space-y-6 overflow-auto">
        {/* Main navigation */}
        <div className="space-y-1">
          <Button variant="default" className="w-full justify-start" size="sm">
            <Plus className="mr-2 h-4 w-4" />
            Compose
          </Button>
        </div>

        {/* Folders section */}
        <Collapsible open={foldersOpen} onOpenChange={setFoldersOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between px-2 font-medium">
              <div className="flex items-center">
                <span className="text-xs font-semibold uppercase tracking-wider">Folders</span>
              </div>
              {foldersOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-1 pt-1">
            {folders.map((folder) => (
              <Button
                key={folder.id}
                variant={currentTab === folder.id ? "secondary" : "ghost"}
                className="w-full justify-start h-9"
                asChild
              >
                <Link href={`/dashboard${folder.id !== "inbox" ? `?tab=${folder.id}` : ""}`}>
                  <folder.icon className="mr-2 h-4 w-4" />
                  <span className="flex-1 text-left">{folder.name}</span>
                  {folder.count > 0 && (
                    <Badge variant="secondary" className="ml-auto">
                      {folder.count}
                    </Badge>
                  )}
                </Link>
              </Button>
            ))}
            <Button variant="ghost" className="w-full justify-start h-9 text-muted-foreground">
              <FolderPlus className="mr-2 h-4 w-4" />
              Create new folder
            </Button>
          </CollapsibleContent>
        </Collapsible>

        {/* Labels section */}
        <Collapsible open={labelsOpen} onOpenChange={setLabelsOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between px-2 font-medium">
              <div className="flex items-center">
                <span className="text-xs font-semibold uppercase tracking-wider">Labels</span>
              </div>
              {labelsOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-1 pt-1">
            {labels.map((label) => (
              <Button key={label.id} variant="ghost" className="w-full justify-start h-9" asChild>
                <Link href={`/dashboard?label=${label.id}`}>
                  <div className={`mr-2 h-3 w-3 rounded-full ${label.color}`} />
                  <span className="flex-1 text-left">{label.name}</span>
                </Link>
              </Button>
            ))}
            <Button variant="ghost" className="w-full justify-start h-9 text-muted-foreground">
              <Tag className="mr-2 h-4 w-4" />
              Create new label
            </Button>
          </CollapsibleContent>
        </Collapsible>

        {/* Settings */}
        <div className="space-y-1">
          <h2 className="px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Settings</h2>
          <Button
            variant={pathname === "/dashboard/profile" ? "secondary" : "ghost"}
            className="w-full justify-start h-9"
            asChild
          >
            <Link href="/dashboard/profile">
              <UserIcon className="mr-2 h-4 w-4" />
              Profile
            </Link>
          </Button>
          <Button
            variant={pathname === "/dashboard/settings" ? "secondary" : "ghost"}
            className="w-full justify-start h-9"
            asChild
          >
            <Link href="/dashboard/settings">
              <Settings className="mr-2 h-4 w-4" />
              Settings
            </Link>
          </Button>
        </div>
      </div>

      {/* Storage usage */}
      <div className="px-4 py-2">
        <div className="flex justify-between text-xs mb-1">
          <span>Storage</span>
          <span>{storageUsed}% of 15 GB used</span>
        </div>
        <Progress value={storageUsed} className="h-1.5" />
      </div>

      {/* User profile and logout */}
      <div className="border-t p-4">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="w-full justify-start p-2">
              <div className="flex items-center w-full">
                <Avatar className="h-8 w-8 mr-2">
                  <AvatarFallback className="bg-primary text-primary-foreground">
                    {user?.username?.substring(0, 2).toUpperCase() || "U"}
                  </AvatarFallback>
                </Avatar>
                <div className="flex-1 overflow-hidden">
                  <p className="text-sm font-medium truncate">{user?.username || "User"}</p>
                  <p className="text-xs text-muted-foreground truncate">{user?.email || ""}</p>
                </div>
                <ChevronDown className="h-4 w-4 ml-2 opacity-70" />
              </div>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <div className="flex items-center justify-start p-2">
              <div className="flex flex-col space-y-1 leading-none">
                <p className="font-medium">{user?.username || "User"}</p>
                <p className="w-[200px] truncate text-xs text-muted-foreground">{user?.email || ""}</p>
              </div>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/dashboard/profile">
                <UserIcon className="mr-2 h-4 w-4" />
                <span>Profile</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/dashboard/settings">
                <Settings className="mr-2 h-4 w-4" />
                <span>Settings</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <div className="flex items-center justify-between p-2">
              <span className="text-xs text-muted-foreground">Theme</span>
              <ModeToggle />
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onLogout}>
              <LogOut className="mr-2 h-4 w-4" />
              <span>Log out</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )

  // For mobile view
  if (typeof window !== "undefined" && window.innerWidth < 768) {
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="left" className="p-0 w-72">
          {sidebarContent}
        </SheetContent>
      </Sheet>
    )
  }

  // For desktop view
  return <div className="hidden w-64 shrink-0 border-r bg-background md:block">{sidebarContent}</div>
}


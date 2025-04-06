"use server"

import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { createClient } from "@/lib/supabase-server"
import bcrypt from 'bcryptjs';
import type { User } from "@/lib/types"

export async function loginUser(email: string, password: string) {
  try {
    const supabase = createClient()

    // Get user from database
    const { data: user, error: userError } = await supabase.from("users").select("*").eq("email", email).single()

    if (userError || !user) {
      return { success: false, error: "Invalid credentials" }
    }

    // Compare password
    const passwordMatch = await bcrypt.compare(password, user.password_hash)

    if (!passwordMatch) {
      return { success: false, error: "Invalid credentials" }
    }

    // Create session
    const sessionId = crypto.randomUUID()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days

    const { error: sessionError } = await supabase.from("sessions").insert({
      id: sessionId,
      user_id: user.id,
      expires_at: expiresAt.toISOString(),
    })

    if (sessionError) {
      return { success: false, error: "Failed to create session" }
    }

    // Set session cookie
    cookies().set("session_id", sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      expires: expiresAt,
      path: "/",
    })

    return { success: true }
  } catch (error) {
    console.error("Login error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function registerUser(email: string, username: string, password: string) {
  try {
    const supabase = createClient()

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("id")
      .or(`email.eq.${email},username.eq.${username}`)
      .maybeSingle()

    if (existingUser) {
      return { success: false, error: "Email or username already exists" }
    }

    // Hash password
    const saltRounds = 10
    const passwordHash = await bcrypt.hash(password, saltRounds)

    // Create user
    const { data: newUser, error: createError } = await supabase
      .from("users")
      .insert({
        email,
        username,
        password_hash: passwordHash,
        created_at: new Date().toISOString(),
      })
      .select()
      .single()

    if (createError) {
      return { success: false, error: "Failed to create user" }
    }

    return { success: true }
  } catch (error) {
    console.error("Registration error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function logoutUser() {
  try {
    const sessionId = cookies().get("session_id")?.value

    if (sessionId) {
      const supabase = createClient()

      // Delete session from database
      await supabase.from("sessions").delete().eq("id", sessionId)

      // Clear session cookie
      cookies().delete("session_id")
    }

    return { success: true }
  } catch (error) {
    console.error("Logout error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function getUserProfile() {
  try {
    const sessionId = cookies().get("session_id")?.value

    if (!sessionId) {
      return { success: false, error: "Not authenticated" }
    }

    const supabase = createClient()

    // Get session
    const { data: session, error: sessionError } = await supabase
      .from("sessions")
      .select("user_id, expires_at")
      .eq("id", sessionId)
      .single()

    if (sessionError || !session) {
      cookies().delete("session_id")
      return { success: false, error: "Invalid session" }
    }

    // Check if session is expired
    if (new Date(session.expires_at) < new Date()) {
      await supabase.from("sessions").delete().eq("id", sessionId)

      cookies().delete("session_id")
      return { success: false, error: "Session expired" }
    }

    // Get user
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, email, username, full_name")
      .eq("id", session.user_id)
      .single()

    if (userError || !user) {
      return { success: false, error: "User not found" }
    }

    const userData: User = {
      id: user.id,
      email: user.email,
      username: user.username,
      fullName: user.full_name || "",
    }

    return { success: true, user: userData }
  } catch (error) {
    console.error("Get user profile error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function updateUserProfile(data: {
  username?: string
  fullName?: string
}) {
  try {
    const sessionId = cookies().get("session_id")?.value

    if (!sessionId) {
      return { success: false, error: "Not authenticated" }
    }

    const supabase = createClient()

    // Get session
    const { data: session, error: sessionError } = await supabase
      .from("sessions")
      .select("user_id")
      .eq("id", sessionId)
      .single()

    if (sessionError || !session) {
      return { success: false, error: "Invalid session" }
    }

    // Update user
    const { error: updateError } = await supabase
      .from("users")
      .update({
        username: data.username,
        full_name: data.fullName,
        updated_at: new Date().toISOString(),
      })
      .eq("id", session.user_id)

    if (updateError) {
      return { success: false, error: "Failed to update profile" }
    }

    return { success: true }
  } catch (error) {
    console.error("Update user profile error:", error)
    return { success: false, error: "An unexpected error occurred" }
  }
}

export async function requireAuth() {
  const sessionId = cookies().get("session_id")?.value

  if (!sessionId) {
    redirect("/login")
  }

  const supabase = createClient()

  // Get session
  const { data: session, error: sessionError } = await supabase
    .from("sessions")
    .select("user_id, expires_at")
    .eq("id", sessionId)
    .single()

  if (sessionError || !session) {
    cookies().delete("session_id")
    redirect("/login")
  }

  // Check if session is expired
  if (new Date(session.expires_at) < new Date()) {
    await supabase.from("sessions").delete().eq("id", sessionId)

    cookies().delete("session_id")
    redirect("/login")
  }

  return session.user_id
}


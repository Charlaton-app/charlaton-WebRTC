import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import jwt from "jsonwebtoken";
import "dotenv/config";
import { JWTUser } from "./types";
import { db } from "./config/firebase";

// ===== Initialize Express App =====
/**
 * Express application instance used to expose HTTP APIs for health checks
 * and read-only helpers (messages history, online users, etc.).
 */
const app = express();

/**
 * Node HTTP server wrapping the Express app.
 * This server is also used as the transport layer for Socket.IO.
 */
const httpServer = createServer(app);

// ===== Parse Environment Variables =====
const PORT = Number(process.env.PORT) || 5050;
const ACCESS_SECRET =
  process.env.ACCESS_SECRET ||
  process.env.JWT_SECRET ||
  "default-secret-change-me";

/**
 * Build the list of allowed CORS origins for both Express and Socket.IO.
 *
 * Priority:
 * 1. `FRONTEND_URL` env var (single origin, usually the production frontend).
 * 2. Additional comma‑separated origins from `ORIGIN`.
 * 3. In non‑production environments, common localhost ports are always allowed.
 *
 * @returns Array of normalized origin URLs.
 */

const getAllowedOrigins = (): string[] => {
  const origins: string[] = [];

  // Add frontend URL if provided
  if (process.env.FRONTEND_URL) {
    let frontendUrl = process.env.FRONTEND_URL.trim();
    if (frontendUrl && !frontendUrl.startsWith("http")) {
      frontendUrl = `https://${frontendUrl}`;
    }
    if (frontendUrl.endsWith("/")) {
      frontendUrl = frontendUrl.slice(0, -1);
    }
    origins.push(frontendUrl);
  }

  // Add additional origins from ORIGIN env variable (comma-separated)
  if (process.env.ORIGIN) {
    const additionalOrigins = process.env.ORIGIN.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    origins.push(...additionalOrigins);
  }

  // Always allow localhost in development
  if (process.env.NODE_ENV !== "production") {
    origins.push("http://localhost:5173", "http://localhost:3000");
  }

  return origins;
};

const allowedOrigins = getAllowedOrigins();

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or Postman)
      if (!origin) {
        return callback(null, true);
      }

      // Allow all origins in development if none configured
      if (
        allowedOrigins.length === 0 &&
        process.env.NODE_ENV !== "production"
      ) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`[CORS] Blocked origin: ${origin}`);
        callback(new Error(`CORS: Not allowed by CORS for origin: ${origin}`));
      }
    },
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

app.use(express.json());

/**
 * Socket.IO server instance responsible for all real‑time communication.
 *
 * - Auth is handled in the `io.use` middleware below.
 * - CORS configuration is shared with the Express app.
 */
const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins.length > 0 ? allowedOrigins : "*",
    credentials: true,
  },
});

// ===== HTTP REST Endpoints =====

/**
 * Basic health‑check endpoint for load‑balancers and uptime monitors.
 *
 * Returns a small JSON payload with service metadata and the
 * number of users currently tracked as online.
 */
app.get("/", (_req, res) => {
  res.json({
    status: "online",
    service: "Charlaton WebRTC Microservice",
    message: "WebRTC server is running",
    version: "1.0.0",
  });
});

/**
 * Lightweight liveness endpoint exposing process uptime and timestamp.
 *
 * This is intentionally small and unauthenticated so that platforms like
 * Render / Railway can use it for health probes.
 */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: Date.now(),
    uptime: process.uptime(),
  });
});

// ===== Socket.IO Authentication Middleware =====
/**
 * Socket.IO middleware that authenticates every incoming connection.
 *
 * The client is expected to pass a JWT in `socket.handshake.auth.token`.
 * The middleware will:
 * 1. Try to verify it as a backend JWT using `ACCESS_SECRET`.
 * 2. If that fails, fall back to verifying it as a Firebase ID token.
 *
 * On success, a lightweight `JWTUser` is attached to `socket.data`.
 * On failure, the connection is rejected with an authentication error.
 */
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      console.warn(`[AUTH] Connection attempt without token from ${socket.id}`);
      return next(new Error("Authentication token required"));
    }

    // Try to verify as backend JWT first
    try {
      const decoded = jwt.verify(token, ACCESS_SECRET) as JWTUser;

      // Store user data in socket
      socket.data.user = decoded;
      socket.data.userId = decoded.id;

      console.log(
        `[AUTH] Backend JWT verified for user ${decoded.email} (${decoded.id})`
      );
      return next();
    } catch (backendJWTError: any) {
      console.log(
        `[AUTH] Backend JWT verification failed, trying Firebase token...`
      );

      // If backend JWT fails, try Firebase ID Token
      try {
        const admin = (await import("./config/firebase")).default;
        const decodedFirebaseToken = await admin.auth().verifyIdToken(token);

        // Store user data from Firebase token
        socket.data.user = {
          id: decodedFirebaseToken.uid,
          email: decodedFirebaseToken.email || "",
        };
        socket.data.userId = decodedFirebaseToken.uid;

        console.log(
          `[AUTH] Firebase token verified for user ${decodedFirebaseToken.email} (${decodedFirebaseToken.uid})`
        );
        return next();
      } catch (firebaseError: any) {
        console.error(
          `[AUTH] Both JWT and Firebase token verification failed from ${socket.id}`
        );
        console.error(`[AUTH] Backend JWT error: ${backendJWTError.message}`);
        console.error(`[AUTH] Firebase error: ${firebaseError.message}`);
        return next(new Error("Invalid authentication token"));
      }
    }
  } catch (err: any) {
    console.error(
      `[AUTH] Authentication error from ${socket.id}:`,
      err.message
    );
    return next(new Error("Authentication error"));
  }
});

// ===== Socket.IO Connection Handler =====
/**
 * Main Socket.IO connection handler.
 *
 * Responsible for:
 * - Joining/leaving rooms.
 * - Broadcasting presence updates (`usersOnline`).
 * - Persisting and broadcasting chat messages.
 * - Cleaning up in‑memory connections on disconnect.
 */

io.on("connection", (socket) => {
  console.log(`[CONNECTION] New WebRTC connection: ${socket.id}`);

  const user = socket.data.user!;

  if (!user) {
    console.error("[CONNECTION] No user data found in socket, disconnecting");
    socket.disconnect(true);
    return;
  }

  async function emitUsers(roomId: string) {
    const sockets = await io.in(roomId).fetchSockets();
    const users = sockets.map((s) => ({
      userId: s.data.userId,
      email: s.data.user?.email,
    }));

    io.to(roomId).emit("usersOnline", users);
  }

  // ===== JOIN ROOM EVENT =====

  socket.on("join_room", async ({ roomId, success }) => {
    // roomId String, success boolean

    try {
      console.log(
        `[ROOM] 👤 User ${user.email} (${socket.data.userId}) attempting to join room ${roomId} in WebRTC server`
      );
      console.log(`[ROOM] 🆔 Socket ID: ${socket.id}, Current roomId: ${socket.data.roomId || 'none'}`);

      if (!roomId) {
        console.error(`[ROOM] ❌ Invalid room ID from ${user.email}`);
        socket.emit("join_room_error", {
          success: false,
          message: "Invalid room ID",
          user: socket.data.user,
        });
        return;
      }
      const roomQuery = await db.collection("rooms").doc(roomId).get();
      if (!roomQuery.exists) {
        console.error(`[ROOM] ❌ Room ${roomId} does not exist in Firestore`);
        socket.emit("join_room_error", {
          success: false,
          message: "404 room does not exist",
          user: socket.data.user,
        });
        return;
      }

      const userId = socket.data.userId || user.id;
      socket.data.roomId = roomId;

      if (!success) {
        console.error(`[ROOM] ❌ Join rejected: success=false from ${user.email}`);
        socket.emit("join_room_error", {
          success: false,
          message: "invalid",
          user: socket.data.user,
        });
        return;
      }

      socket.join(roomId);
      console.log(`[ROOM] ✅ User ${user.email} joined WebRTC room ${roomId} successfully`);

      socket.emit("join_room_success", {
        user: socket.data.user,
        message: "estado WebRTC funcionando",
        success: true,
      });
      console.log(`[ROOM] 📤 Emitted join_room_success to ${user.email}`);
      
      socket.to(roomId).emit("user_joined", user);
      console.log(`[ROOM] 📢 Broadcast user_joined to room ${roomId}`);
      
      await emitUsers(roomId);
      console.log(`[ROOM] 👥 Emitted usersOnline for room ${roomId}`);
    } catch (error) {
      console.error(`[ROOM] ❌ join_room error for ${user.email}:`, error);
      socket.emit("join_room_error", {
        success: false,
        message: "Error in server",
        user: socket.data.user,
      });
      return;
    }
  });

  // ===== WebRTC SIGNALS =====

  socket.on("webrtc_offer", async ({ roomId, targetUserId, sdp }) => {
    console.log(`[WEBRTC] 📡 Offer from ${socket.data.userId} to ${targetUserId} in room ${roomId}`);
    // Buscar socket del target en la sala
    const room = io.sockets.adapter.rooms.get(roomId);

    if (socket.data.roomId !== roomId) {
      console.error(`[WEBRTC] ❌ Offer rejected: sender not in room ${roomId}`);
      socket.emit("webrtc_error", {
        message: "Not in this room",
        success: false,
      });
      return;
    }

    if (!room) {
      console.error(`[WEBRTC] ❌ Room ${roomId} not found for offer`);
      return;
    }
    for (const sockId of room) {
      const s = io.sockets.sockets.get(sockId);
      if (s && s.data.userId === targetUserId) {
        s.emit("webrtc_offer", {
          senderId: socket.data.userId,
          sdp,
        });
        console.log(`[WEBRTC] ✅ Offer forwarded to ${targetUserId}`);
        break;
      }
    }
  });

  // Cuando alguien envía una respuesta WebRTC
  socket.on("webrtc_answer", async ({ roomId, targetUserId, sdp }) => {
    console.log(`[WEBRTC] 📡 Answer from ${socket.data.userId} to ${targetUserId} in room ${roomId}`);
    const room = io.sockets.adapter.rooms.get(roomId);
    if (!room) {
      console.error(`[WEBRTC] ❌ Room ${roomId} not found for answer`);
      return;
    }

    if (socket.data.roomId !== roomId) {
      console.error(`[WEBRTC] ❌ Answer rejected: sender not in room ${roomId}`);
      socket.emit("webrtc_error", {
        message: "Not in this room",
        success: false,
      });
      return;
    }

    for (const sockId of room) {
      const s = io.sockets.sockets.get(sockId);

      if (s && s.data.userId === targetUserId) {
        s.emit("webrtc_answer", {
          senderId: socket.data.userId,
          sdp,
        });
        console.log(`[WEBRTC] ✅ Answer forwarded to ${targetUserId}`);
        break;
      }
    }
  });

  // Cuando alguien envia sus ICE candidates
  socket.on(
    "webrtc_ice_candidate",
    async ({ roomId, targetUserId, candidate }) => {
      console.log(`[WEBRTC] 🧊 ICE candidate from ${socket.data.userId} to ${targetUserId} in room ${roomId}`);
      const room = io.sockets.adapter.rooms.get(roomId);
      if (!room) {
        console.error(`[WEBRTC] ❌ Room ${roomId} not found for ICE candidate`);
        return;
      }

      if (socket.data.roomId !== roomId) {
        console.error(`[WEBRTC] ❌ ICE rejected: sender not in room ${roomId}`);
        socket.emit("webrtc_error", {
          message: "Not in this room",
          success: false,
        });
        return;
      }

      for (const sockId of room) {
        const s = io.sockets.sockets.get(sockId);

        if (s && s.data.userId === targetUserId) {
          s.emit("webrtc_ice_candidate", {
            senderId: socket.data.userId,
            candidate,
          });
          console.log(`[WEBRTC] ✅ ICE candidate forwarded to ${targetUserId}`);
          break;
        }
      }
    }
  );

  // ========== DISCONNECT ==========
  socket.on("disconnect", async () => {
    const roomId = socket.data.roomId;
    console.log(`[DISCONNECT] 👋 User ${user.email} (${socket.id}) disconnected from room ${roomId || 'none'}`);
    if (roomId) {
      socket.to(roomId).emit("user_left", user);
      console.log(`[DISCONNECT] 📢 Broadcast user_left for ${user.email} in room ${roomId}`);
      await emitUsers(roomId);
      console.log(`[DISCONNECT] 👥 Updated usersOnline for room ${roomId}`);
    }
  });

  // ===== END ROOM (HOST) EVENT =====
  /**
   * Allows host to end the meeting on WebRTC server as well.
   * Broadcasts 'room_ended' to the room and makes sockets leave.
   */
  socket.on("end_room", async () => {
    const roomId = socket.data.roomId;
    if (!roomId) return;
    console.log(`[ROOM] 🔚 (WebRTC) Ending room ${roomId} by ${socket.data.userId}`);
    io.to(roomId).emit("room_ended", {
      success: true,
      roomId,
      message: "La reunión ha sido finalizada por el anfitrión",
    });

    const room = io.sockets.adapter.rooms.get(roomId);
    if (room) {
      for (const socketId of room) {
        const s = io.sockets.sockets.get(socketId);
        if (s) {
          s.leave(roomId);
        }
      }
    }
    console.log(`[ROOM] ✅ (WebRTC) Room ${roomId} ended and sockets left`);
  });
});

// ===== Start Server =====
httpServer.listen(PORT, () => {
  console.log("=".repeat(70));
  console.log(
    `[SERVER] 🚀 Charlaton WebRTC Microservice running on port ${PORT}`
  );
  console.log(`[CORS] 🌐 Allowed origins: ${allowedOrigins.join(", ")}`);
  console.log(`[FIREBASE] 🔥 Admin SDK initialized`);
  console.log(`[AUTH] 🔐 JWT authentication enabled`);
  console.log("=".repeat(70));
});

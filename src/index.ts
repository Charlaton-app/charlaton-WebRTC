import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import jwt from "jsonwebtoken";
import "dotenv/config";
import { JWTUser } from "./types";
import { db } from "./config/firebase";
import { send } from "process";


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
const ACCESS_SECRET = process.env.ACCESS_SECRET || process.env.JWT_SECRET || "default-secret-change-me";

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
        if (allowedOrigins.length === 0 && process.env.NODE_ENV !== "production") {
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
const io = new Server(
    httpServer,
    {
      cors: {
        origin: allowedOrigins.length > 0 ? allowedOrigins : "*",
        credentials: true,
      },
    }
);

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
        
        console.log(`[AUTH] Backend JWT verified for user ${decoded.email} (${decoded.id})`);
        return next();
      } catch (backendJWTError: any) {
        console.log(`[AUTH] Backend JWT verification failed, trying Firebase token...`);
        
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
          
          console.log(`[AUTH] Firebase token verified for user ${decodedFirebaseToken.email} (${decodedFirebaseToken.uid})`);
          return next();
        } catch (firebaseError: any) {
          console.error(`[AUTH] Both JWT and Firebase token verification failed from ${socket.id}`);
          console.error(`[AUTH] Backend JWT error: ${backendJWTError.message}`);
          console.error(`[AUTH] Firebase error: ${firebaseError.message}`);
          return next(new Error("Invalid authentication token"));
        }
      }
    } catch (err: any) {
      console.error(`[AUTH] Authentication error from ${socket.id}:`, err.message);
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

io.on("connection",(socket) => {

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
          id: s.data.userId || s.data.user?.id,
          userId: s.data.userId || s.data.user?.id,
          email: s.data.user?.email,
          displayName: s.data.user?.displayName,
          nickname: s.data.user?.nickname,
          user: s.data.user,
        }));
    
        console.log(`[EMIT_USERS] Emitting ${users.length} users for room ${roomId}`);
        io.to(roomId).emit("usersOnline", users);
    }

    

    // ===== JOIN ROOM EVENT =====

    socket.on("join_room", async ({roomId, success}) => { // roomId String, success boolean

        try {

            console.log(`[ROOM] 👤 User ${user.email} attempting to join room ${roomId} in WebRTC server`);

            if (!roomId) {
                socket.emit("join_room_error", {
                  success: false,
                  message: "Invalid room ID",
                  user: socket.data.user,
                });
                return;
            }
            const roomQuery = await db.collection("rooms").doc(roomId).get();
            if(!roomQuery.exists){
                socket.emit("join_room_error", {success: false, message: "404 room does not exist", user: socket.data.user});
                return;
            }
    
            const userId = socket.data.userId || user.id;
            socket.data.roomId = roomId;
    
            if (!success){
                socket.emit("join_room_error", {success: false, message: "invalid", user: socket.data.user});
                return;
            }
    
            socket.join(roomId);
            
            console.log(`[ROOM] ✅ User ${user.email} joined WebRTC room ${roomId}`);

            // Emit join success to the user first
            socket.emit("join_room_success", { user: socket.data.user, message: "estado WebRTC funcionando", success: true });
            
            // Notify others that this user joined
            socket.to(roomId).emit("user_joined", {
                id: userId,
                userId: userId,
                email: user.email,
                displayName: user.displayName,
                nickname: user.nickname,
                user: socket.data.user
            });
            
            // Send list of users to everyone (including the new user)
            await emitUsers(roomId);
            
            console.log(`[ROOM] 📡 Broadcasted user list for room ${roomId}`);

        } catch (error) {
            console.error("join_room error:", error);
            socket.emit("join_room_error", {success: false, message: "Error in server", user: socket.data.user});
            return;
        }
    
    });

    // ===== WebRTC SIGNALS =====

    socket.on("webrtc_offer", async ({ roomId, targetUserId, sdp }) => {
        const userRoomId = socket.data.roomId;
        
        if (!roomId || !targetUserId || !sdp) {
            console.error("[OFFER] Missing parameters");
            return;
        }

        if (userRoomId !== roomId) {
            socket.emit("webrtc_error", { message: "Not in this room", success: false });
            return;
        }
        
        const userId = socket.data.userId || socket.data.user?.id;
        console.log(`[OFFER] Forwarding offer from ${userId} to ${targetUserId}`);
    
        // Send to specific user
        const sockets = await io.in(roomId).fetchSockets();
        const targetSocket = sockets.find(s => 
            (s.data.userId === targetUserId || s.data.user?.id === targetUserId) && s.id !== socket.id
        );
        
        if (targetSocket) {
            targetSocket.emit("webrtc_offer", {
                senderId: userId,
                sdp,
            });
        } else {
            console.error(`[OFFER] Target user ${targetUserId} not found in room`);
        }
    });
    
      // Cuando alguien envía una respuesta WebRTC
    socket.on("webrtc_answer", async ({ roomId, targetUserId, sdp }) => {
        const userRoomId = socket.data.roomId;
        
        if (!roomId || !targetUserId || !sdp) {
            console.error("[ANSWER] Missing parameters");
            return;
        }

        if (userRoomId !== roomId) {
            socket.emit("webrtc_error", { message: "Not in this room", success: false });
            return;
        }
        
        const userId = socket.data.userId || socket.data.user?.id;
        console.log(`[ANSWER] Forwarding answer from ${userId} to ${targetUserId}`);
    
        // Send to specific user
        const sockets = await io.in(roomId).fetchSockets();
        const targetSocket = sockets.find(s => 
            (s.data.userId === targetUserId || s.data.user?.id === targetUserId) && s.id !== socket.id
        );
        
        if (targetSocket) {
            targetSocket.emit("webrtc_answer", {
                senderId: userId,
                sdp,
            });
        } else {
            console.error(`[ANSWER] Target user ${targetUserId} not found in room`);
        }
    });
    
    
      // Cuando alguien envia sus ICE candidates
    socket.on("webrtc_ice_candidate", async ({ roomId, targetUserId, candidate }) => {
        const userRoomId = socket.data.roomId;
        
        if (!roomId || !targetUserId || !candidate) {
            console.error("[ICE] Missing parameters");
            return;
        }

        if (userRoomId !== roomId) {
            socket.emit("webrtc_error", { message: "Not in this room", success: false });
            return;
        }
        
        const userId = socket.data.userId || socket.data.user?.id;
        console.log(`[ICE] Forwarding ICE candidate from ${userId} to ${targetUserId}`);
    
        // Send to specific user
        const sockets = await io.in(roomId).fetchSockets();
        const targetSocket = sockets.find(s => 
            (s.data.userId === targetUserId || s.data.user?.id === targetUserId) && s.id !== socket.id
        );
        
        if (targetSocket) {
            targetSocket.emit("webrtc_ice_candidate", {
                senderId: userId,
                candidate,
            });
        }
    });

    // ========== DISCONNECT ==========
    socket.on("disconnect", async () => {
        const roomId = socket.data.roomId;
        if (roomId) {
            const userId = socket.data.userId || user.id;
            console.log(`[DISCONNECT] User ${user.email} (${userId}) left room ${roomId}`);
            
            socket.to(roomId).emit("user_left", {
                id: userId,
                userId: userId,
                email: user.email,
                displayName: user.displayName,
                nickname: user.nickname,
                user: socket.data.user
            });
            
            await emitUsers(roomId);
        }
    });


});

// ===== Start Server =====
httpServer.listen(PORT, () => {
    console.log("=".repeat(70));
    console.log(`[SERVER] 🚀 Charlaton WebRTC Microservice running on port ${PORT}`);
    console.log(`[CORS] 🌐 Allowed origins: ${allowedOrigins.join(", ")}`);
    console.log(`[FIREBASE] 🔥 Admin SDK initialized`);
    console.log(`[AUTH] 🔐 JWT authentication enabled`);
    console.log("=".repeat(70));
});
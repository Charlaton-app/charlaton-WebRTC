/**
 * @file Firebase Admin SDK Configuration
 * @description Initializes Firebase Admin SDK for Firestore access using credentials
 * provided via environment variables. Exports the Firestore database instance and
 * the initialized admin SDK.
 */

import admin from "firebase-admin";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";

dotenv.config();

let serviceAccount: admin.ServiceAccount;

/**
 * Loads Firebase service account credentials from environment variables.
 * Throws an error if credentials are not found.
 */
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.log(
    "[FIREBASE] Loading credentials from FIREBASE_SERVICE_ACCOUNT env"
  );
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else if (process.env.FIREBASE_KEY_PATH) {
  const firebaseKeyPath = path.isAbsolute(process.env.FIREBASE_KEY_PATH)
    ? process.env.FIREBASE_KEY_PATH
    : path.resolve(process.cwd(), process.env.FIREBASE_KEY_PATH);

  if (!fs.existsSync(firebaseKeyPath)) {
    throw new Error(
      `Firebase key file not found at: ${firebaseKeyPath}\n` +
        `Current working directory: ${process.cwd()}\n` +
        `Set FIREBASE_KEY_PATH to point to your service account file.`
    );
  }

  serviceAccount = require(firebaseKeyPath);
} else {
  throw new Error(
    "Firebase credentials not found. Set FIREBASE_SERVICE_ACCOUNT (JSON string) or FIREBASE_KEY_PATH (file path)."
  );
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

/**
 * Firestore database instance.
 * @type {FirebaseFirestore.Firestore}
 */
export const db = admin.firestore();

/**
 * Initialized Firebase Admin SDK.
 * @type {admin.app.App}
 */
export default admin;

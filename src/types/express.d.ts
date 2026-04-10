import type { AppSession } from "./index.js";

declare global {
  namespace Express {
    interface Request {
      appSession?: AppSession;
    }
  }
}

export {};

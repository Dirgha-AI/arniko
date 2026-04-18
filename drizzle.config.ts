import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dbCredentials: {
    url: process.env.ARNIKO_DATABASE_URL || process.env.DATABASE_URL || "postgresql://localhost:5432/dirgha_arniko",
  },
});

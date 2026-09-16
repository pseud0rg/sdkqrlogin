import { LoginPanel } from "./login-panel";

export default function Page() {
  return (
    <main>
      <h1>Local Next.js App Router QR login</h1>
      <p>The browser SDK renders the QR locally; no protocol value is logged or stored.</p>
      <LoginPanel />
    </main>
  );
}

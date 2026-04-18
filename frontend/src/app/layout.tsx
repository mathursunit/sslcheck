import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'TrustIssues | Handshake Verification & Security Intelligence',
  description: 'Because verifying the handshake shouldn\'t be a gamble. Deep SSL analysis and diagnostics.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet" />
      </head>
      <body>{children}</body>
    </html>
  );
}

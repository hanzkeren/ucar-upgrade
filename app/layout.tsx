export const metadata = {
  title: 'Cloaker',
  description: 'Edge Middleware Cloaking',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}


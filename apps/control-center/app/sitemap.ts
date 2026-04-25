import { MetadataRoute } from 'next'

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: 'https://www.vibefixing.me',
      lastModified: new Date(),
      changeFrequency: 'monthly',
      priority: 1,
    },
    {
      url: 'https://www.vibefixing.me/blog/voice-phishing-langchain-agent',
      lastModified: new Date('2026-04-25'),
      changeFrequency: 'monthly',
      priority: 0.9,
    },
  ]
}

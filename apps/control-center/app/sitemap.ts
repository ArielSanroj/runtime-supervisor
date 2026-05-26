import { MetadataRoute } from "next";
import fs from "node:fs";
import path from "node:path";

const SITE = "https://www.vibefixing.me";

type Entry = MetadataRoute.Sitemap[number];

function blogEntries(): Entry[] {
  const blogDir = path.join(process.cwd(), "app", "blog");
  let dirents: fs.Dirent[] = [];
  try {
    dirents = fs.readdirSync(blogDir, { withFileTypes: true });
  } catch {
    return [];
  }

  return dirents
    .filter((d) => d.isDirectory())
    .map<Entry | null>((d) => {
      const postFile = path.join(blogDir, d.name, "page.tsx");
      let lastModified: Date;
      try {
        lastModified = fs.statSync(postFile).mtime;
      } catch {
        return null;
      }
      return {
        url: `${SITE}/blog/${d.name}`,
        lastModified,
        changeFrequency: "monthly",
        priority: 0.9,
      };
    })
    .filter((e): e is Entry => e !== null);
}

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  const core: Entry[] = [
    { url: `${SITE}`, lastModified: now, changeFrequency: "monthly", priority: 1 },
    { url: `${SITE}/scan`, lastModified: now, changeFrequency: "weekly", priority: 0.95 },
    { url: `${SITE}/risks`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
    { url: `${SITE}/benchmark`, lastModified: now, changeFrequency: "weekly", priority: 0.88 },
    { url: `${SITE}/compliance`, lastModified: now, changeFrequency: "monthly", priority: 0.85 },
    { url: `${SITE}/enterprise/nist-rmf`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${SITE}/blog`, lastModified: now, changeFrequency: "weekly", priority: 0.8 },
  ];

  return [...core, ...blogEntries()];
}

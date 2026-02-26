import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

export const GET: APIRoute = async () => {
  const skills = await getCollection('skills');
  const sorted = skills.sort((a, b) => b.data.date.localeCompare(a.data.date) || b.data.id.localeCompare(a.data.id));

  const items = sorted.map(skill => `    <item>
      <title>${escapeXml(skill.data.id + ': ' + skill.data.title)}</title>
      <link>https://troyskills.ai/skill/${skill.data.id}</link>
      <guid>https://troyskills.ai/skill/${skill.data.id}</guid>
      <pubDate>${new Date(skill.data.date).toUTCString()}</pubDate>
      <description>${escapeXml(skill.data.description)}</description>
      <category>${escapeXml(skill.data.category)}</category>
    </item>`).join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>TroySkills — AI Agent Malicious Skills Database</title>
    <link>https://troyskills.ai</link>
    <description>New malicious AI agent skill patterns as they are documented.</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <atom:link href="https://troyskills.ai/rss.xml" rel="self" type="application/rss+xml"/>
${items}
  </channel>
</rss>`;

  return new Response(rss, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

export const GET: APIRoute = async () => {
  const skills = await getCollection('skills');
  const patterns = skills
    .sort((a, b) => a.data.id.localeCompare(b.data.id))
    .map(s => ({
      id: s.data.id,
      title: s.data.title,
      category: s.data.category,
      severity: s.data.severity,
      description: s.data.description,
      date: s.data.date,
      tags: s.data.tags || [],
    }));
  return new Response(JSON.stringify(patterns, null, 2), {
    headers: { 'Content-Type': 'application/json' },
  });
};

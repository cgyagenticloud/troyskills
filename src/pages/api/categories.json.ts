import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

const categoryNames: Record<string, string> = {
  P1: 'Prompt Injection',
  P2: 'Data Exfiltration',
  P3: 'Privilege Escalation',
  P4: 'Malicious Scripts',
  P5: 'Config Tampering',
  P6: 'Social Engineering',
  P7: 'Supply Chain',
};

export const GET: APIRoute = async () => {
  const skills = await getCollection('skills');
  const cats = Object.entries(categoryNames).map(([id, name]) => {
    const patterns = skills.filter(s => s.data.category === id);
    const severities: Record<string, number> = {};
    patterns.forEach(p => {
      severities[p.data.severity] = (severities[p.data.severity] || 0) + 1;
    });
    return { id, name, count: patterns.length, severities };
  });
  return new Response(JSON.stringify(cats, null, 2), {
    headers: { 'Content-Type': 'application/json' },
  });
};

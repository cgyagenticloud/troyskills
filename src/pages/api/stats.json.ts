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
  const severityDist: Record<string, number> = {};
  const categoryDist: Record<string, { name: string; count: number }> = {};

  skills.forEach(s => {
    severityDist[s.data.severity] = (severityDist[s.data.severity] || 0) + 1;
    if (!categoryDist[s.data.category]) {
      categoryDist[s.data.category] = { name: categoryNames[s.data.category], count: 0 };
    }
    categoryDist[s.data.category].count++;
  });

  return new Response(JSON.stringify({
    totalPatterns: skills.length,
    totalCategories: Object.keys(categoryDist).length,
    severity: severityDist,
    categories: categoryDist,
    lastUpdated: new Date().toISOString().split('T')[0],
  }, null, 2), {
    headers: { 'Content-Type': 'application/json' },
  });
};

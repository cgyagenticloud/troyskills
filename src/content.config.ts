import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const skills = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/skills' }),
  schema: z.object({
    id: z.string(),
    title: z.string(),
    category: z.enum(['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7']),
    severity: z.enum(['Critical', 'High', 'Medium', 'Low']),
    description: z.string(),
    date: z.string(),
    author: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }),
});

export const collections = { skills };

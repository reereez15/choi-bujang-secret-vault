import { readFileSync } from 'node:fs';
import { createNotesApi } from '../../src/notes-handler.mjs';

const loadConfig = () => JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));

// GET·PUT·DELETE /api/notes/:id
export default createNotesApi({ loadConfig }).item;

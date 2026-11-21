export type D1Summary = { uuid: string; name: string; created_at?: string };
type Read = <T>(path: string) => Promise<T>;

/**
 * Finds a D1 database by exact name. The list API returns 100 databases per page and its
 * `name` filter matches substrings, so an unfiltered first page can miss an existing
 * database in a large account. Filter by name, page through, then match exactly.
 */
export async function findD1Database(api: Read, accountId: string, name: string): Promise<D1Summary | null> {
  for (let page = 1; page <= 100; page++) {
    const rows = await api<D1Summary[]>("/accounts/" + accountId + "/d1/database?name=" +
      encodeURIComponent(name) + "&per_page=100&page=" + page);
    if (!Array.isArray(rows)) throw Error("Unable to list D1 databases");
    const match = rows.find(d => d.name === name);
    if (match) return match;
    if (rows.length < 100) return null;
  }
  throw Error("D1 inventory exceeds the safe discovery limit");
}

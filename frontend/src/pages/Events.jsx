import { useState } from "react";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { Empty, ErrorBanner, EventTable, Loading, Pager } from "../components/ui";

const EMPTY = { q: "", source_ip: "", username: "", event_type: "", status: "" };

export default function Events() {
  const [draft, setDraft] = useState(EMPTY);
  const [filters, setFilters] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useAsync(() => api.events({ ...filters, page, page_size: 50 }), [filters, page]);
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value });
  const apply = (e) => { e.preventDefault(); setPage(1); setFilters(draft); };

  return (
    <>
      <div className="page-head"><div><h1>Event explorer</h1><p>Normalized security events stored in the database.</p></div></div>
      <form className="panel row" onSubmit={apply} role="search">
        <label>Search<input type="search" value={draft.q} onChange={set("q")} placeholder="message, user or IP" /></label>
        <label>Source IP<input type="text" value={draft.source_ip} onChange={set("source_ip")} /></label>
        <label>User<input type="text" value={draft.username} onChange={set("username")} /></label>
        <label>Event type<select value={draft.event_type} onChange={set("event_type")}><option value="">Any</option><option value="authentication">authentication</option><option value="network_connection">network_connection</option><option value="resource_access">resource_access</option></select></label>
        <label>Status<select value={draft.status} onChange={set("status")}><option value="">Any</option><option value="success">success</option><option value="failure">failure</option><option value="denied">denied</option></select></label>
        <button type="submit">Apply filters</button>
        <button type="button" className="ghost" onClick={() => { setDraft(EMPTY); setFilters(EMPTY); setPage(1); }}>Reset</button>
      </form>
      <ErrorBanner error={error} onRetry={reload} />
      {loading && !data && <Loading what="events" />}
      {data && (
        <div className="panel">
          {data.items.length === 0 ? <Empty title="No events match">Adjust the filters, or load data on the Log ingestion page.</Empty> : <EventTable events={data.items} />}
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
        </div>
      )}
    </>
  );
}

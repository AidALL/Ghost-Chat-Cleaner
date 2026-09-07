async function collectChatMetadata(requestedIds, authenticationOnly = false, controlGroups = authenticationOnly ? [] : [requestedIds]) {
  // Only this sanitized result crosses CDP. Never return session JSON, JWTs,
  // headers, error response bodies, or conversation bodies to the native app.
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const fail = code => { throw new Error(code); };
  const abort = new AbortController();
  let deadlineFired = false;
  const deadline = setTimeout(() => { deadlineFired = true; abort.abort(); }, authenticationOnly ? 15000 : 110000);
  const errors = new Set(['wrong_origin','invalid_request','login_required','session_user_mismatch','account_match_none','account_match_multiple','ordered_personal_account_id_missing_bound','ordered_personal_account_id_missing_unbound','account_user_mismatch','final_identity_changed','unsupported_account','authorization_failed','rate_limited','web_unavailable','response_schema_changed','positive_control_missing','no_positive_control']);
  try {
    if (location.origin !== 'https://chatgpt.com') fail('wrong_origin');
    if (typeof authenticationOnly !== 'boolean' || !Array.isArray(requestedIds) || (!authenticationOnly && !requestedIds.length) || (authenticationOnly && requestedIds.length) || requestedIds.length > 10000 || requestedIds.some(id => typeof id !== 'string' || !uuid.test(id)) || new Set(requestedIds).size !== requestedIds.length) fail('invalid_request');
    const requested = new Set(requestedIds);
    if (!Array.isArray(controlGroups) || controlGroups.length > 10000 || (authenticationOnly ? controlGroups.length !== 0 : controlGroups.length === 0)) fail('invalid_request');
    const grouped = new Set();
    let memberships = 0;
    for (const group of controlGroups) {
      if (!Array.isArray(group) || !group.length || (memberships += group.length) > 10000 || new Set(group).size !== group.length || group.some(id => !requested.has(id))) fail('invalid_request');
      for (const id of group) grouped.add(id);
    }
    if (grouped.size !== requested.size) fail('invalid_request');
    async function get(path, headers = {}, statusOnly = false) {
      if (!(path === '/api/auth/session' || path.startsWith('/backend-api/'))) fail('invalid_request');
      const response = await fetch(path, { method:'GET', credentials:'same-origin', cache:'no-store', redirect:'error', headers, signal:abort.signal });
      if (response.status === 401 || response.status === 403) fail('authorization_failed');
      if (response.status === 429) fail('rate_limited');
      const isJson = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'application/json';
      if (statusOnly && (response.status === 200 || response.status === 404)) {
        if (!isJson) fail('response_schema_changed');
        if (response.body) await response.body.cancel();
        return response.status;
      }
      if (response.status !== 200) fail('web_unavailable');
      if (!isJson) fail('response_schema_changed');
      const result = await response.json();
      if (!result || typeof result !== 'object' || Array.isArray(result)) fail('response_schema_changed');
      return result;
    }
    async function mapFour(items, action) {
      const results = new Array(items.length);
      let next = 0, failed = false, firstError;
      async function worker() {
        while (!failed && !abort.signal.aborted) {
          const index = next++;
          if (index >= items.length) return;
          try {
            results[index] = await action(items[index]);
          } catch (error) {
            if (!failed) {
              failed = true;
              firstError = error;
              // Preserve the first failure while sibling cancellations settle.
              clearTimeout(deadline);
              abort.abort();
            }
          }
        }
      }
      // Workers catch failures so every in-flight request settles before return.
      await Promise.all(Array.from({length:Math.min(4,items.length)},worker));
      if (failed) throw firstError;
      if (deadlineFired) fail('collection_timeout');
      return results;
    }
    function claims(token) {
      try {
        const segment = token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
        const payload = JSON.parse(atob(segment));
        const auth = payload['https://api.openai.com/auth'];
        const user = auth?.chatgpt_user_id ?? auth?.user_id;
        if (!auth || !uuid.test(auth.chatgpt_account_id) || typeof user !== 'string' || !/^user-[A-Za-z0-9]+$/.test(user)) fail('response_schema_changed');
        if (auth.chatgpt_user_id != null && auth.user_id != null && auth.chatgpt_user_id !== auth.user_id) fail('response_schema_changed');
        return {account:auth.chatgpt_account_id,user};
      } catch { fail('response_schema_changed'); }
    }
    function sessionIdentity(session) {
      if (typeof session.accessToken !== 'string' || !session.accessToken) fail('login_required');
      const identity = claims(session.accessToken);
      if (session.user?.id !== identity.user) fail('session_user_mismatch');
      return identity;
    }
    const session = await get('/api/auth/session');
    const identity = sessionIdentity(session);
    const headers = {Authorization:'Bearer '+session.accessToken,'ChatGPT-Account-Id':identity.account};
    const accounts = await get('/backend-api/accounts/check/v4-2023-04-27', headers);
    if (!accounts.accounts || typeof accounts.accounts !== 'object' || Array.isArray(accounts.accounts)) fail('response_schema_changed');
    const ordering = accounts.account_ordering;
    if (!Array.isArray(ordering) || !ordering.length || ordering.length > 1000 || ordering.some(key => typeof key !== 'string' || !key.length || key.length > 1000 || !Object.prototype.hasOwnProperty.call(accounts.accounts,key)) || new Set(ordering).size !== ordering.length) fail('response_schema_changed');
    const accessibleAccounts = [];
    for (const key of ordering) {
      const entry = accounts.accounts[key];
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) fail('response_schema_changed');
      if (entry.can_access_with_session === false) continue;
      const account = entry.account;
      if (!account || typeof account !== 'object' || Array.isArray(account) || (account.account_id != null && typeof account.account_id !== 'string')) fail('response_schema_changed');
      accessibleAccounts.push(account);
    }
    const matchingAccounts = accessibleAccounts.filter(account => account.account_id === identity.account);
    if (matchingAccounts.length === 0) {
      const missingPersonalId = accessibleAccounts.some(account => account.structure === 'personal' && account.account_id == null);
      if (missingPersonalId) {
        const sessionAccountBound = session.account?.id === identity.account && session.account?.structure === 'personal';
        fail(sessionAccountBound ? 'ordered_personal_account_id_missing_bound' : 'ordered_personal_account_id_missing_unbound');
      }
      fail('account_match_none');
    }
    // Ordered aliases may describe the same account using bare or qualified user
    // IDs. Validate every representation before selecting a canonical one.
    for (const candidate of matchingAccounts) {
      if (candidate.account_user_id !== identity.user && candidate.account_user_id !== identity.user+'__'+identity.account) fail('account_user_mismatch');
      if (candidate.structure !== 'personal') fail('unsupported_account');
    }
    const account = matchingAccounts[0];
    if (authenticationOnly) {
      const finalIdentity = sessionIdentity(await get('/api/auth/session'));
      if (finalIdentity.user !== identity.user || finalIdentity.account !== identity.account) fail('final_identity_changed');
      // Connection status is not comparison evidence and cannot authorize cleanup.
      return {authenticated:true};
    }
    // Metadata supplies positive evidence only. Changing totals, overlapping
    // pages and a bounded incomplete listing never establish absence.
    const listed = new Set();
    let pages = 0;
    metadata: for (const [archived,starred] of [[false,false],[false,true],[true,null]]) {
      let offset = 0;
      while (pages < 100) {
        const query = new URLSearchParams({offset:String(offset),limit:'30',order:'updated',is_archived:String(archived)});
        if (starred !== null) query.set('is_starred',String(starred));
        const page = await get('/backend-api/conversations?'+query,headers);
        pages++;
        if (!Number.isSafeInteger(page.offset) || page.offset !== offset || !Number.isSafeInteger(page.limit) || page.limit < 1 || page.limit > 30 || !Number.isSafeInteger(page.total) || page.total < 0 || !Array.isArray(page.items) || page.items.length > page.limit) fail('response_schema_changed');
        for (const item of page.items) {
          if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.id !== 'string' || !uuid.test(item.id)) fail('response_schema_changed');
          if (requested.has(item.id)) listed.add(item.id);
        }
        if (listed.size === requested.size) break metadata;
        offset += page.limit;
        if (!page.items.length || offset >= page.total) break;
      }
    }
    // Only IDs omitted from the partial listing need direct checks. JSON 404
    // means endpoint-unavailable, never deletion or complete-history absence.
    const direct=await mapFour(requestedIds.filter(id=>!listed.has(id)),async id=>{
      const status=await get('/backend-api/conversation/'+id,headers,true);
      return {id,evidence:status===200?'authenticated_json_get_200':'authenticated_json_get_404'};
    });
    const evidence = new Map([...listed].map(id=>[id,'authenticated_list_item']));
    for (const check of direct) evidence.set(check.id,check.evidence);
    const checks = requestedIds.map(id=>({id,evidence:evidence.get(id)}));
    const hasNegative = group=>group.some(id=>evidence.get(id)==='authenticated_json_get_404');
    const isPositive = id=>evidence.get(id)==='authenticated_list_item'||evidence.get(id)==='authenticated_json_get_200';
    const selectedControls = new Set();
    for (const group of controlGroups) {
      if (!hasNegative(group)) continue;
      const control = group.find(id=>selectedControls.has(id)) ?? group.find(isPositive);
      if (control !== undefined) selectedControls.add(control);
    }
    // One direct 200 per covered negative group, after all requested statuses.
    // Native validation still requires a control bound to the exact local host.
    const controls=await mapFour([...selectedControls],async id=>{
      if (await get('/backend-api/conversation/'+id,headers,true) !== 200) fail('positive_control_missing');
      return id;
    });
    if (hasNegative(requestedIds) && !controls.length) fail('no_positive_control');
    const finalSession=await get('/api/auth/session');
    const finalIdentity=sessionIdentity(finalSession);
    if (finalIdentity.user !== identity.user || finalIdentity.account !== identity.account) fail('final_identity_changed');
    return {schema_version:3,kind:'requested_metadata_checks',user_id:identity.user,account_id:identity.account,account_user_id:account.account_user_id,account_structure:account.structure,complete:true,checks,controls};
  } catch (error) {
    return {error:deadlineFired?'collection_timeout':errors.has(error?.message)?error.message:'web_unavailable'};
  } finally {
    clearTimeout(deadline);
    abort.abort();
  }
}

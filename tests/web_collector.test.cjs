const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(new URL('../assets/web/collect.js', `file://${__filename}`), 'utf8');
const known = '00000000-0000-0000-0000-000000000001';
const missing = '00000000-0000-0000-0000-000000000002';
const account = '00000000-0000-0000-0000-000000000003';
const token = 'fixture.' + Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account,chatgpt_user_id:'user-fixture'}})).toString('base64url') + '.fixture';
function response(status, value, contentType = 'application/json') { return {status, ok:status>=200&&status<300, headers:{get:()=>contentType}, body:{cancel:async()=>{}}, json:async()=>value}; }
async function run(override=()=>undefined, authenticationOnly=false, requestedIds=[known,missing], runtime={}, controlGroups) {
  const calls=[];
  const fetch=async(path,options)=>{
    calls.push({path,options});
    const changed=override(path,options,calls);
    if(changed) return changed;
    if(path==='/api/auth/session') return response(200,{accessToken:token,user:{id:'user-fixture'}});
    if(path.includes('/accounts/check/')) return response(200,{accounts:{[account]:{account:{account_id:account,account_user_id:'user-fixture__'+account,structure:'personal'}}},account_ordering:[account]});
    if(path.startsWith('/backend-api/conversations?')) {
      const u=new URL(path,'https://chatgpt.com');
      const active=u.searchParams.get('is_archived')==='false' && u.searchParams.get('is_starred')==='false';
      return response(200,{items:active?[{id:known,title:'fixture'}]:[],total:active?1:0,offset:0,limit:30});
    }
    if(path==='/backend-api/conversation/'+known) return response(200,{});
    if(path==='/backend-api/conversation/'+missing) return response(404,{});
    throw new Error('unexpected path');
  };
  const context=vm.createContext({fetch,location:{origin:'https://chatgpt.com'},AbortController,setTimeout,clearTimeout,URL,URLSearchParams,atob:x=>Buffer.from(x,'base64').toString('binary'),...runtime});
  const groupArgument=controlGroups===undefined?'':','+JSON.stringify(controlGroups);
  const result=await vm.runInContext(source+';collectChatMetadata('+JSON.stringify(authenticationOnly?[]:requestedIds)+','+JSON.stringify(authenticationOnly)+groupArgument+')',context);
  return {result:JSON.parse(JSON.stringify(result)),calls};
}
test('delayed requests use four slots with exact order and strict phase barriers',async()=>{
  const ids=Array.from({length:18},(_,i)=>'00000000-0000-0000-0000-'+String(i+10).padStart(12,'0'));
  const positives=ids.slice(0,9),groups=positives.map((id,i)=>[id,ids[i+9]]);
  const seen=new Map(),active=[0,0],maximum=[0,0],finished=[0,0];
  let barrierViolation=false,cancelled=0;
  const {result}=await run((path)=>{
    if(path==='/api/auth/session' && seen.size) barrierViolation ||= finished[1]!==positives.length;
    if(!path.startsWith('/backend-api/conversation/')) return;
    const id=path.split('/').pop(),phase=seen.get(id)||0;
    seen.set(id,phase+1);
    barrierViolation ||= phase===1 && finished[0]!==ids.length;
    maximum[phase]=Math.max(maximum[phase],++active[phase]);
    return new Promise(resolve=>setTimeout(()=>{
      active[phase]--;finished[phase]++;
      const reply=response(positives.includes(id)?200:404,{});
      reply.body.cancel=async()=>{cancelled++;};
      resolve(reply);
    },ids.indexOf(id)%4===0?12:2));
  },false,ids,{},groups);
  assert.equal(result.complete,true);
  assert.deepEqual(maximum,[4,4]);
  assert.deepEqual(active,[0,0]);
  assert.equal(barrierViolation,false);
  assert.deepEqual(result.checks.map(check=>check.id),ids);
  assert.deepEqual(result.controls,positives);
  assert.equal(cancelled,ids.length+positives.length);
});
for(const failurePhase of [0,1]) {
  test(`phase ${failurePhase+1} failure aborts and awaits every active request without replacing the first error`,async()=>{
    const ids=Array.from({length:8},(_,i)=>'00000000-0000-0000-0000-'+String(i+10).padStart(12,'0'));
    const groups=ids.slice(0,4).map((id,i)=>[id,ids[i+4]]);
    const seen=new Map();
    let active=0,failedPhaseStarted=0,aborted=0,settled=0;
    const {result,calls}=await run((path,options)=>{
      if(!path.startsWith('/backend-api/conversation/')) return;
      const id=path.split('/').pop(),phase=seen.get(id)||0;
      seen.set(id,phase+1);
      if(phase!==failurePhase) return response(ids.indexOf(id)<4?200:404,{});
      failedPhaseStarted++;active++;
      return new Promise((resolve,reject)=>{
        const finish=()=>{active--;settled++;options.signal.removeEventListener('abort',onAbort);};
        const timer=setTimeout(()=>{finish();resolve(response(id===ids[0]?429:200,{}));},id===ids[0]?5:100);
        const onAbort=()=>{
          aborted++;clearTimeout(timer);
          // Simulate cancellation completing asynchronously; return must await it.
          setTimeout(()=>{finish();reject(new Error('private abort details'));},10);
        };
        options.signal.addEventListener('abort',onAbort,{once:true});
      });
    },false,ids,{},groups);
    assert.deepEqual(result,{error:'rate_limited'});
    assert.equal(failedPhaseStarted,4);
    assert.equal(aborted,3);
    assert.equal(active,0);
    assert.equal(settled,4);
    assert.equal(calls.filter(call=>call.path==='/api/auth/session').length,1);
    assert.ok([...seen.values()].every(count=>count<=failurePhase+1));
  });
}
test('only the collector deadline is classified as collection_timeout',async()=>{
  let active=0,aborted=0;
  const {result}=await run((path,options)=>{
    if(path.startsWith('/backend-api/conversations?')) return response(200,{items:[],total:0,offset:0,limit:30});
    if(!path.startsWith('/backend-api/conversation/')) return;
    active++;
    return new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>{
      aborted++;
      setTimeout(()=>{active--;reject(new Error('private deadline details'));},5);
    },{once:true}));
  },false,[known,missing],{setTimeout:callback=>setTimeout(callback,5)});
  assert.deepEqual(result,{error:'collection_timeout'});
  assert.equal(aborted,2);
  assert.equal(active,0);
  const generic=await run(path=>{
    if(path.startsWith('/backend-api/conversation/')) throw new Error('AbortError');
  });
  assert.deepEqual(generic.result,{error:'web_unavailable'});
});
test('requested metadata proof queries only unknown IDs and the necessary control',async()=>{
  const {result,calls}=await run();
  assert.equal(result.schema_version,3);
  assert.equal(result.kind,'requested_metadata_checks');
  assert.equal(result.complete,true);
  assert.deepEqual(result.checks,[
    {id:known,evidence:'authenticated_list_item'},
    {id:missing,evidence:'authenticated_json_get_404'},
  ]);
  assert.deepEqual(result.controls,[known]);
  assert.ok(!('items' in result));
  assert.equal(calls.filter(c=>c.path.startsWith('/backend-api/conversations?')).length,3);
  assert.equal(calls.filter(c=>c.path==='/backend-api/conversation/'+known).length,1);
  assert.equal(calls.filter(c=>c.path==='/backend-api/conversation/'+missing).length,1);
  assert.ok(calls.every(c=>c.options.method==='GET' && c.options.redirect==='error'));
  assert.ok(!JSON.stringify(result).includes(token));
});
test('finding every requested ID stops metadata paging and avoids all direct queries',async()=>{
  const {result,calls}=await run(()=>undefined,false,[known]);
  assert.equal(result.complete,true);
  assert.deepEqual(result.checks,[{id:known,evidence:'authenticated_list_item'}]);
  assert.deepEqual(result.controls,[]);
  assert.equal(calls.filter(call=>call.path.includes('/conversations?')).length,1);
  assert.equal(calls.filter(call=>call.path.includes('/conversation/')).length,0);
  assert.ok(!JSON.stringify(result).includes('fixture-title-never-export'));
});
test('ordinary starred and archived metadata are positive-only partitions',async()=>{
  const third='00000000-0000-0000-0000-000000000004';
  const partitions=[];
  const {result,calls}=await run(path=>{
    if(!path.includes('/conversations?')) return;
    const query=new URL(path,'https://chatgpt.com').searchParams;
    partitions.push([query.get('is_archived'),query.get('is_starred')]);
    assert.equal(query.get('order'),'updated');
    return response(200,{items:[{id:[known,missing,third][partitions.length-1],title:'fixture-title-never-export'}],total:1,offset:0,limit:30});
  },false,[known,missing,third]);
  assert.deepEqual(partitions,[['false','false'],['false','true'],['true',null]]);
  assert.ok(result.checks.every(check=>check.evidence==='authenticated_list_item'));
  assert.equal(calls.filter(call=>call.path.includes('/conversation/')).length,0);
  assert.ok(!JSON.stringify(result).includes('fixture-title-never-export'));
});
test('changing totals and duplicate metadata never establish absence or fail the sweep',async()=>{
  const offsets=[];
  const {result,calls}=await run(path=>{
    if(!path.includes('/conversations?')) return;
    const query=new URL(path,'https://chatgpt.com').searchParams;
    const offset=Number(query.get('offset'));
    if(query.get('is_archived')==='false'&&query.get('is_starred')==='false') {
      offsets.push(offset);
      return response(200,{items:[{id:known},{id:known}],total:offset===0?100:31,offset,limit:30});
    }
    return response(200,{items:[{id:known}],total:1,offset,limit:30});
  });
  assert.equal(result.complete,true);
  assert.deepEqual(offsets,[0,30]);
  assert.equal(result.checks.find(check=>check.id===missing).evidence,'authenticated_json_get_404');
  assert.equal(calls.filter(call=>call.path==='/backend-api/conversation/'+missing).length,1);
});
test('the global metadata page cap falls back to exact direct checks',async()=>{
  const offsets=[];
  const {result,calls}=await run(path=>{
    if(!path.includes('/conversations?')) return;
    const offset=Number(new URL(path,'https://chatgpt.com').searchParams.get('offset'));
    offsets.push(offset);
    return response(200,{items:[{id:known}],total:100000,offset,limit:30});
  });
  assert.equal(result.complete,true);
  assert.equal(offsets.length,100);
  assert.equal(offsets[99],2970);
  assert.equal(calls.filter(call=>call.path==='/backend-api/conversation/'+missing).length,1);
});
test('metadata HTTP and content-type failures block proof without retries',async()=>{
  for(const [status,type,code] of [[200,'text/html','response_schema_changed'],[401,'application/json','authorization_failed'],[403,'application/json','authorization_failed'],[429,'application/json','rate_limited'],[500,'application/json','web_unavailable']]) {
    const {result,calls}=await run(path=>path.includes('/conversations?')?response(status,{},type):undefined);
    assert.deepEqual(result,{error:code});
    assert.equal(calls.filter(call=>call.path.includes('/conversations?')).length,1);
    assert.equal(calls.filter(call=>call.path.includes('/conversation/')).length,0);
  }
});
test('malformed metadata pagination and item identities cannot become evidence',async()=>{
  const good={items:[{id:known}],total:1,offset:0,limit:30};
  for(const change of [{offset:1},{offset:-1},{limit:0},{limit:31},{total:-1},{total:1.5},{items:null},{items:[null]},{items:[{id:'not-an-id'}]},{items:Array.from({length:31},()=>({id:known}))}]) {
    const {result}=await run(path=>path.includes('/conversations?')?response(200,{...good,...change}):undefined);
    assert.deepEqual(result,{error:'response_schema_changed'});
  }
});
test('control groups cover exactly requested IDs before any request',async()=>{
  for(const groups of [null,[],[[]],[[known]],[[known,missing,account]],[[known,known,missing]],[known],Array.from({length:10001},()=>[known,missing]),Array.from({length:5001},()=>[known,missing])]) {
    const {result,calls}=await run(()=>undefined,false,[known,missing],{},groups);
    assert.deepEqual(result,{error:'invalid_request'});
    assert.equal(calls.length,0);
  }
  const auth=await run(()=>undefined,true,[],{},[[known]]);
  assert.deepEqual(auth.result,{error:'invalid_request'});
  assert.equal(auth.calls.length,0);
});
test('one direct positive control covers each negative group with deduplicated overlap',async()=>{
  const positive='00000000-0000-0000-0000-000000000004';
  const negative='00000000-0000-0000-0000-000000000005';
  const ids=[known,missing,positive,negative];
  const groups=[[known,missing],[known,positive,negative],[positive,negative],[negative]];
  const direct=[];
  const {result}=await run(path=>{
    if(path.includes('/conversations?')) return response(200,{items:[{id:known},{id:positive}],total:2,offset:0,limit:30});
    if(path.includes('/conversation/')) {
      const id=path.split('/').pop();direct.push(id);
      return response([known,positive].includes(id)?200:404,{});
    }
  },false,ids,{},groups);
  assert.equal(result.complete,true);
  assert.deepEqual(result.controls,[known,positive]);
  assert.deepEqual(direct.slice(0,2),[missing,negative]);
  assert.deepEqual(direct.slice(2),[known,positive]);
  assert.deepEqual(result.checks.map(check=>check.id),ids);
  // The group containing only a negative contributes no control; native validation keeps it unknown.
});
test('a positive from an unrelated control group cannot enable a negative-only group',async()=>{
  const {result,calls}=await run(()=>undefined,false,[known,missing],{},[[known],[missing]]);
  assert.deepEqual(result,{error:'no_positive_control'});
  assert.equal(calls.filter(call=>call.path==='/backend-api/conversation/'+known).length,0);
});
test('all direct 404 results cannot establish a positive control',async()=>{
  const {result}=await run(p=>p.startsWith('/backend-api/conversations?')?response(200,{items:[],total:0,offset:0,limit:30}):p.startsWith('/backend-api/conversation/')?response(404,{}):undefined);
  assert.deepEqual(result,{error:'no_positive_control'});
});
test('a listed control must return direct 200 after all requested statuses',async()=>{
  const {result}=await run(p=>p==='/backend-api/conversation/'+known?response(404,{}):undefined);
  assert.deepEqual(result,{error:'positive_control_missing'});
});
test('all-present results need no negative controls or repeated direct requests',async()=>{
  const {result,calls}=await run(p=>p.startsWith('/backend-api/conversation/')?response(200,{}):undefined);
  assert.deepEqual(result.controls,[]);
  assert.equal(result.checks[0].evidence,'authenticated_list_item');
  assert.equal(result.checks[1].evidence,'authenticated_json_get_200');
  assert.equal(calls.filter(c=>c.path.startsWith('/backend-api/conversation/')).length,1);
});
test('conversation bodies are cancelled without parsing or returning their content',async()=>{
  let cancelled=0;
  const {result}=await run(p=>p.startsWith('/backend-api/conversation/')?{
    status:p.endsWith(known)?200:404,
    headers:{get:()=> 'application/json'},
    body:{cancel:async()=>{cancelled++;}},
    json:async()=>{throw new Error('conversation body must not be read');},
  }:undefined);
  assert.equal(result.complete,true);
  assert.equal(cancelled,2);
});
for(const status of [401,403,429,500]) {
  test(`direct HTTP ${status} blocks the complete proof`,async()=>{
    const {result}=await run(p=>p==='/backend-api/conversation/'+missing?response(status,{}):undefined);
    assert.deepEqual(result,{error:status===429?'rate_limited':status===500?'web_unavailable':'authorization_failed'});
  });
}
test('logged-out session cannot yield proof',async()=>{
  const {result}=await run(p=>p==='/api/auth/session'?response(200,{}):undefined);
  assert.deepEqual(result,{error:'login_required'});
});
test('fetch failure cannot leak exception details or a partial proof',async()=>{
  const {result}=await run(p=>{if(p==='/backend-api/conversation/'+missing)throw new Error('private diagnostic value');});
  assert.deepEqual(result,{error:'web_unavailable'});
});
test('invalid or duplicate requested IDs are rejected before any network request',async()=>{
  for(const ids of [[],[known,known],['not-a-uuid'],new Array(10001).fill(known)]) {
    const {result,calls}=await run(()=>undefined,false,ids);
    assert.deepEqual(result,{error:'invalid_request'});
    assert.equal(calls.length,0);
  }
});
test('personal account lookup matches nested identity under a default map key',async()=>{
  const {result}=await run(p=>p.includes('/accounts/check/')?response(200,{
    accounts:{default:{account:{account_id:account,account_user_id:'user-fixture__'+account,structure:'personal'}}},
    account_ordering:['default'],
  }):undefined);
  assert.equal(result.complete,true);
  assert.equal(result.account_id,account);
});
test('consistent ordered aliases represent one verified personal account',async()=>{
  const entry={account:{account_id:account,account_user_id:'user-fixture__'+account,structure:'personal'}};
  const bare={account:{...entry.account,account_user_id:'user-fixture'}};
  for (const authenticationOnly of [false,true]) {
    const {result}=await run(p=>p.includes('/accounts/check/')?response(200,{
      accounts:{[account]:entry,default:bare},account_ordering:[account,'default'],
    }):undefined,authenticationOnly);
    assert.equal(authenticationOnly?result.authenticated:result.complete,true);
  }
});

test('unordered aliases do not override the canonical account ordering',async()=>{
  const {result}=await run(p=>p.includes('/accounts/check/')?response(200,{
    accounts:{default:{account:{account_id:account,account_user_id:'user-fixture',structure:'personal'}},
      stale:{account:{account_id:account,account_user_id:'user-other',structure:'workspace'}}},account_ordering:['default'],
  }):undefined,true);
  assert.deepEqual(result,{authenticated:true});
});

test('all accessible ordered same-account aliases must agree on user and personal structure',async()=>{
  for (const authenticationOnly of [false,true]) {
    for (const [change,code] of [[{account_user_id:'user-other'},'account_user_mismatch'],[{structure:'workspace'},'unsupported_account']]) {
      const canonical={account_id:account,account_user_id:'user-fixture',structure:'personal'};
      const {result}=await run(p=>p.includes('/accounts/check/')?response(200,{
        accounts:{default:{account:canonical},alias:{account:{...canonical,...change}}},account_ordering:['default','alias'],
      }):undefined,authenticationOnly);
      assert.deepEqual(result,{error:code});
    }
  }
});

test('malformed account ordering or ordered entries never authenticate',async()=>{
  const entry={account:{account_id:account,account_user_id:'user-fixture',structure:'personal'}};
  const oversized=Array.from({length:1001},(_,i)=>'alias'+i);
  const cases=[
    {accounts:{default:entry}},
    ...[null,{},[],['default','default'],[1],[''],['toString'],['absent']].map(account_ordering=>({accounts:{default:entry},account_ordering})),
    ...[null,[],{account:null},{account:[]}].map(value=>({accounts:{default:value},account_ordering:['default']})),
    {accounts:Object.fromEntries(oversized.map(key=>[key,entry])),account_ordering:oversized},
  ];
  for (const payload of cases) {
    const {result}=await run(p=>p.includes('/accounts/check/')?response(200,payload):undefined,true);
    assert.deepEqual(result,{error:'response_schema_changed'});
  }
});

test('inaccessible ordered accounts cannot establish authentication',async()=>{
  const {result}=await run(p=>p.includes('/accounts/check/')?response(200,{
    accounts:{default:{can_access_with_session:false,account:{account_id:account,account_user_id:'user-fixture',structure:'personal'}}},account_ordering:['default'],
  }):undefined,true);
  assert.deepEqual(result,{error:'account_match_none'});
});
for (const status of [200,404]) {
  test(`HTML ${status} from a direct lookup cannot be conversation evidence`,async()=>{
    const {result}=await run(p=>p==='/backend-api/conversation/'+missing?response(status,{},'text/html; charset=utf-8'):undefined);
    assert.equal(result.error,'response_schema_changed');
    assert.notEqual(result.complete,true);
  });
}
test('the documented user_id token fallback binds to the session user',async()=>{
  const fallbackToken='fixture.'+Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account,user_id:'user-fixture'}})).toString('base64url')+'.fixture';
  const {result}=await run(p=>p==='/api/auth/session'?response(200,{accessToken:fallbackToken,user:{id:'user-fixture'}}):undefined);
  assert.equal(result.complete,true);
  assert.equal(result.user_id,'user-fixture');
  assert.ok(!JSON.stringify(result).includes(fallbackToken));
});
test('a session user that differs from its token blocks comparison',async()=>{
  const {result}=await run(p=>p==='/api/auth/session'?response(200,{accessToken:token,user:{id:'user-other'}}):undefined);
  assert.equal(result.error,'session_user_mismatch');
});
test('conflicting token user claims block comparison',async()=>{
  const conflictingToken='fixture.'+Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account,chatgpt_user_id:'user-fixture',user_id:'user-other'}})).toString('base64url')+'.fixture';
  const {result}=await run(p=>p==='/api/auth/session'?response(200,{accessToken:conflictingToken,user:{id:'user-fixture'}}):undefined);
  assert.equal(result.error,'response_schema_changed');
});
test('a changed final session user invalidates collected absence evidence',async()=>{
  let sessions=0;
  const {result}=await run(p=>p==='/api/auth/session'&&++sessions===2?response(200,{accessToken:token,user:{id:'user-other'}}):undefined);
  assert.equal(result.error,'session_user_mismatch');
  assert.notEqual(result.complete,true);
});
test('authentication probe returns only validated connection state without conversation queries',async()=>{
  const {result,calls}=await run(()=>undefined,true);
  assert.deepEqual(result,{authenticated:true});
  assert.ok(calls.some(call=>call.path.includes('/accounts/check/')));
  assert.equal(calls.filter(call=>call.path==='/api/auth/session').length,2);
  assert.ok(calls.every(call=>!call.path.includes('/conversations')&&!call.path.includes('/conversation/')));
});
test('expired or wrong-account authentication probe never reports connected',async()=>{
  for (const override of [
    p=>p==='/api/auth/session'?response(200,{}):undefined,
    p=>p.includes('/accounts/check/')?response(401,{}):undefined,
    p=>p==='/api/auth/session'?response(200,{accessToken:token,user:{id:'user-other'}}):undefined,
  ]) {
    const {result}=await run(override,true);
    assert.notEqual(result.authenticated,true);
    assert.notEqual(result.error,'invalid_request');
  }
});

test('account failures identify only the fixed failing branch in both collection modes',async()=>{
  const changedToken='fixture.'+Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account,chatgpt_user_id:'user-other'}})).toString('base64url')+'.fixture';
  const cases=[
    ['session_user_mismatch',()=>p=>p==='/api/auth/session'?response(200,{accessToken:token,user:{id:'user-other'}}):undefined],
    ['account_match_none',()=>p=>p.includes('/accounts/check/')?response(200,{accounts:{other:{account:{account_id:'00000000-0000-0000-0000-000000000099',account_user_id:'user-fixture',structure:'personal'}}},account_ordering:['other']}):undefined],
    ['account_user_mismatch',()=>p=>p.includes('/accounts/check/')?response(200,{accounts:{default:{account:{account_id:account,account_user_id:'user-other',structure:'personal'}}},account_ordering:['default']}):undefined],
    ['final_identity_changed',()=>{
      let sessions=0;
      return p=>p==='/api/auth/session'&&++sessions===2?response(200,{accessToken:changedToken,user:{id:'user-other'}}):undefined;
    }],
  ];
  for (const authenticationOnly of [false,true]) {
    for (const [code,override] of cases) {
      const {result}=await run(override(),authenticationOnly);
      assert.deepEqual(result,{error:code});
    }
  }
});

test('missing account match distinguishes only ordered personal entries without an ID',async()=>{
  const cases=[
    [{accounts:{default:{account:{structure:'personal'}}},account_ordering:['default']},'ordered_personal_account_id_missing_unbound'],
    [{accounts:{default:{account:{structure:'personal',account_id:null}}},account_ordering:['default']},'ordered_personal_account_id_missing_unbound'],
    [{accounts:{default:{account:{structure:'personal',account_id:null}}},account_ordering:['default']},'ordered_personal_account_id_missing_bound',{id:account,structure:'personal'}],
    [{accounts:{default:{account:{structure:'personal',account_id:null}}},account_ordering:['default']},'ordered_personal_account_id_missing_unbound',{id:account,structure:'workspace'}],
    [{accounts:{default:{account:{structure:'personal',account_id:null}}},account_ordering:['default']},'ordered_personal_account_id_missing_unbound',{id:'00000000-0000-0000-0000-000000000099',structure:'personal'}],
    [{accounts:{default:{can_access_with_session:false,account:{structure:'personal',account_id:null}}},account_ordering:['default']},'account_match_none',{id:account,structure:'personal'}],
    [{accounts:{default:{account:{structure:'personal',account_id:null}}},account_ordering:[]},'response_schema_changed'],
    [{accounts:{default:{account:{structure:'workspace',account_id:null}}},account_ordering:['default']},'account_match_none'],
    [{accounts:{default:{account:{structure:'personal',account_id:'00000000-0000-0000-0000-000000000099'}}},account_ordering:['default']},'account_match_none'],
  ];
  for (const authenticationOnly of [false,true]) {
    for (const [payload,code,sessionAccount] of cases) {
      const {result}=await run(p=>p.includes('/accounts/check/')?response(200,payload):
        p==='/api/auth/session'&&sessionAccount?response(200,{accessToken:token,user:{id:'user-fixture'},account:sessionAccount}):undefined,authenticationOnly);
      assert.deepEqual(result,{error:code});
    }
  }
});

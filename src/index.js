const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const SESSION_SECONDS = 60 * 60 * 24 * 14;
const FREE_MONTHLY_LIMIT = 10;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function fail(message, status = 400) { return json({ error: message }, status); }
function uid() { return crypto.randomUUID(); }
function bytesToHex(bytes) { return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex) { return new Uint8Array((hex.match(/.{1,2}/g) || []).map(x => parseInt(x, 16))); }
function randomToken() { const b = crypto.getRandomValues(new Uint8Array(32)); return btoa(String.fromCharCode(...b)).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
async function sha256(value) { return bytesToHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))); }
async function derivePassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:hexToBytes(saltHex), iterations:210000, hash:"SHA-256" }, key, 256);
  return bytesToHex(bits);
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
function clearCookie() { return "bb_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"; }
function getCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  const part = raw.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : "";
}
function cleanString(v, max = 500) { return String(v ?? "").trim().slice(0, max); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function safeUser(row) { return { id:row.id, name:row.name, email:row.email, role:row.role, plan:row.plan, createdAt:row.created_at }; }
function monthKey() { const d = new Date(); return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}`; }

async function currentUser(request, env) {
  const token = getCookie(request, "bb_session");
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT u.id,u.name,u.email,u.role,u.plan,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(tokenHash, Math.floor(Date.now()/1000)).first();
  return row || null;
}
async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user ? { user } : { response: fail("Please sign in to continue.", 401) };
}
async function getUsage(env, user) {
  const key = monthKey();
  const row = await env.DB.prepare("SELECT generations FROM usage WHERE user_id=? AND month_key=?").bind(user.id,key).first();
  const used = row?.generations || 0;
  return { used, limit: user.plan === "pro" || user.role === "admin" ? null : FREE_MONTHLY_LIMIT, month:key };
}
async function saveUsage(env, user) {
  const key = monthKey();
  await env.DB.prepare(`INSERT INTO usage(id,user_id,month_key,generations) VALUES(?,?,?,1)
    ON CONFLICT(user_id,month_key) DO UPDATE SET generations=generations+1`).bind(uid(),user.id,key).run();
}

async function handleApi(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "GET" && path === "/api/health") return json({ ok:true, app:"AgentGrow AI" });

  if (method === "POST" && path === "/api/auth/register") {
    const body = await request.json().catch(() => null);
    if (!body) return fail("Invalid request body.");
    const name = cleanString(body.name,100), email = cleanString(body.email,190).toLowerCase(), password = String(body.password || "");
    if (name.length < 2) return fail("Please enter your full name.");
    if (!validEmail(email)) return fail("Please enter a valid email address.");
    if (password.length < 10) return fail("Use a password with at least 10 characters.");
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    if (exists) return fail("An account with this email already exists.",409);
    const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await derivePassword(password,salt);
    const id = uid();
    const role = email === cleanString(env.ADMIN_EMAIL,190).toLowerCase() ? "admin" : "user";
    await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,password_salt,role,plan) VALUES(?,?,?,?,?,?,?)")
      .bind(id,name,email,hash,salt,role,"free").run();
    const token = randomToken(), tokenHash = await sha256(token), expires = Math.floor(Date.now()/1000)+SESSION_SECONDS;
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(tokenHash,id,expires).run();
    return json({ user:{id,name,email,role,plan:"free"}, usage:{used:0,limit:role==="admin"?null:FREE_MONTHLY_LIMIT,month:monthKey()} },201,{ "set-cookie":cookie("bb_session",token,SESSION_SECONDS) });
  }

  if (method === "POST" && path === "/api/auth/login") {
    const body = await request.json().catch(() => null);
    if (!body) return fail("Invalid request body.");
    const email = cleanString(body.email,190).toLowerCase(), password = String(body.password || "");
    const row = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    if (!row) return fail("Email or password is incorrect.",401);
    const hash = await derivePassword(password,row.password_salt);
    if (hash !== row.password_hash) return fail("Email or password is incorrect.",401);
    const token = randomToken(), tokenHash = await sha256(token), expires = Math.floor(Date.now()/1000)+SESSION_SECONDS;
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(tokenHash,row.id,expires).run();
    const user = safeUser(row);
    return json({ user, usage:await getUsage(env,row) },200,{ "set-cookie":cookie("bb_session",token,SESSION_SECONDS) });
  }

  if (method === "POST" && path === "/api/auth/logout") {
    const token = getCookie(request,"bb_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ok:true},200,{ "set-cookie":clearCookie() });
  }

  const auth = await requireUser(request,env);
  if (auth.response) return auth.response;
  const user = auth.user;

  if (method === "GET" && path === "/api/me") {
    return json({user:safeUser(user),usage:await getUsage(env,user)});
  }


  if (method === "POST" && path === "/api/auth/change-password") {
    const body = await request.json().catch(()=>null);
    if (!body || String(body.newPassword||"").length < 10) return fail("New password must contain at least 10 characters.");
    const row = await env.DB.prepare("SELECT password_hash,password_salt FROM users WHERE id=?").bind(user.id).first();
    if (await derivePassword(String(body.currentPassword||""),row.password_salt) !== row.password_hash) return fail("Current password is incorrect.",401);
    const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await derivePassword(String(body.newPassword),salt);
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=? WHERE id=?").bind(hash,salt,user.id).run();
    return json({ok:true});
  }

  if (method === "GET" && path === "/api/dashboard") {
    const [p,c,u] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) n FROM properties WHERE user_id=?").bind(user.id).first(),
      env.DB.prepare("SELECT COUNT(*) n FROM campaigns WHERE user_id=?").bind(user.id).first(),
      getUsage(env,user)
    ]);
    const recent = await env.DB.prepare("SELECT id,property_title,created_at FROM campaigns WHERE user_id=? ORDER BY created_at DESC LIMIT 5").bind(user.id).all();
    return json({properties:p.n,campaigns:c.n,usage:u,recent:recent.results});
  }

  if (path === "/api/properties" && method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM properties WHERE user_id=? ORDER BY updated_at DESC").bind(user.id).all();
    return json({properties:result.results});
  }
  if (path === "/api/properties" && method === "POST") {
    const b = await request.json().catch(()=>null); if (!b) return fail("Invalid property details.");
    const required = ["title","bhk","priceValue","priceUnit","location","city","carpetArea","brokerName","brokerPhone"];
    for (const k of required) if (!cleanString(b[k],300)) return fail(`Please complete ${k}.`);
    const id=uid();
    await env.DB.prepare(`INSERT INTO properties(id,user_id,title,bhk,price_value,price_unit,location,city,carpet_area,rera_number,vastu_compliant,amenities,broker_name,broker_phone)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,user.id,cleanString(b.title,180),cleanString(b.bhk,20),cleanString(b.priceValue,30),cleanString(b.priceUnit,10),cleanString(b.location,120),cleanString(b.city,100),cleanString(b.carpetArea,30),cleanString(b.reraNumber,100),b.vastuCompliant?1:0,cleanString(b.amenities,1000),cleanString(b.brokerName,100),cleanString(b.brokerPhone,30)).run();
    return json({id},201);
  }
  const propMatch = path.match(/^\/api\/properties\/([a-f0-9-]+)$/i);
  if (propMatch && method === "PUT") {
    const b=await request.json().catch(()=>null); if(!b) return fail("Invalid property details.");
    const result=await env.DB.prepare(`UPDATE properties SET title=?,bhk=?,price_value=?,price_unit=?,location=?,city=?,carpet_area=?,rera_number=?,vastu_compliant=?,amenities=?,broker_name=?,broker_phone=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?`)
      .bind(cleanString(b.title,180),cleanString(b.bhk,20),cleanString(b.priceValue,30),cleanString(b.priceUnit,10),cleanString(b.location,120),cleanString(b.city,100),cleanString(b.carpetArea,30),cleanString(b.reraNumber,100),b.vastuCompliant?1:0,cleanString(b.amenities,1000),cleanString(b.brokerName,100),cleanString(b.brokerPhone,30),propMatch[1],user.id).run();
    return result.meta.changes ? json({ok:true}) : fail("Property not found.",404);
  }
  if (propMatch && method === "DELETE") {
    const exists=await env.DB.prepare("SELECT id FROM properties WHERE id=? AND user_id=?").bind(propMatch[1],user.id).first();
    if (!exists) return fail("Property not found.",404);
    await env.DB.prepare("DELETE FROM properties WHERE id=? AND user_id=?").bind(propMatch[1],user.id).run();
    return json({ok:true});
  }

  // Broker-owned transaction ledger. Every query is scoped to the signed-in broker.
  if (path === "/api/transactions" && method === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM transactions WHERE user_id=? ORDER BY transaction_date DESC, created_at DESC LIMIT 1000").bind(user.id).all();
    const summary = await env.DB.prepare(`SELECT COUNT(*) total, COALESCE(SUM(deal_value),0) deal_value,
      COALESCE(SUM(commission_amount),0) commission_total, COALESCE(SUM(commission_paid),0) commission_paid
      FROM transactions WHERE user_id=? AND transaction_status='Closed'`).bind(user.id).first();
    return json({transactions:rows.results,summary});
  }
  if (path === "/api/transactions" && method === "POST") {
    const b=await request.json().catch(()=>null); if(!b) return fail("Invalid transaction details.");
    const required=["transactionDate","transactionType","propertyType","propertyTitle","propertyAddress","city","dealValue"];
    for(const k of required) if(!cleanString(b[k],300)) return fail(`Please complete ${k}.`);
    if(!cleanString(b.buyerName,120) && !cleanString(b.sellerName,120)) return fail("Enter at least the buyer or seller name.");
    const deal=Number(b.dealValue), rate=Number(b.commissionRate||0), amount=Number(b.commissionAmount||0), paid=Number(b.commissionPaid||0), share=Number(b.coBrokerShare||0), gst=Number(b.gstAmount||0), tds=Number(b.tdsDeducted||0);
    if(!Number.isFinite(deal)||deal<0||!Number.isFinite(rate)||rate<0||rate>100||!Number.isFinite(amount)||amount<0||!Number.isFinite(paid)||paid<0||paid>amount||!Number.isFinite(share)||share<0||!Number.isFinite(gst)||gst<0||!Number.isFinite(tds)||tds<0) return fail("Check the deal value, commission and payment amounts.");
    const id=uid(), ref=cleanString(b.transactionRef,60)||`BB-${new Date().getFullYear()}-${id.slice(0,8).toUpperCase()}`;
    const propertyId=cleanString(b.propertyId,80);
    if(propertyId && !await env.DB.prepare("SELECT id FROM properties WHERE id=? AND user_id=?").bind(propertyId,user.id).first()) return fail("Selected property was not found in your account.",404);
    await env.DB.prepare(`INSERT INTO transactions(id,user_id,property_id,transaction_ref,transaction_date,transaction_type,property_type,property_title,property_address,locality,city,state,pincode,buyer_name,buyer_phone,buyer_email,seller_name,seller_phone,seller_email,deal_value,commission_rate,commission_amount,commission_status,commission_paid,commission_paid_date,commission_invoice_no,commission_invoice_date,gst_amount,tds_deducted,broker_side,payment_method,payment_reference,transaction_status,lead_source,co_broker_name,co_broker_share,notes)
      VALUES(${Array(37).fill('?').join(',')})`).bind(id,user.id,propertyId||null,ref,cleanString(b.transactionDate,10),cleanString(b.transactionType,30),cleanString(b.propertyType,60),cleanString(b.propertyTitle,180),cleanString(b.propertyAddress,250),cleanString(b.locality,120),cleanString(b.city,100),cleanString(b.state,100),cleanString(b.pincode,12),cleanString(b.buyerName,120),cleanString(b.buyerPhone,30),cleanString(b.buyerEmail,190),cleanString(b.sellerName,120),cleanString(b.sellerPhone,30),cleanString(b.sellerEmail,190),deal,rate,amount,cleanString(b.commissionStatus,30)||'Pending',paid,cleanString(b.commissionPaidDate,10),cleanString(b.commissionInvoiceNo,80),cleanString(b.commissionInvoiceDate,10),gst,tds,cleanString(b.brokerSide,20)||'Both',cleanString(b.paymentMethod,50),cleanString(b.paymentReference,100),cleanString(b.transactionStatus,30)||'Closed',cleanString(b.leadSource,80),cleanString(b.coBrokerName,120),share,cleanString(b.notes,2000)).run();
    return json({id,transactionRef:ref},201);
  }
  const transactionMatch=path.match(/^\/api\/transactions\/([a-f0-9-]+)$/i);
  if(transactionMatch && method==="PUT") {
    const b=await request.json().catch(()=>null); if(!b) return fail("Invalid transaction details.");
    const deal=Number(b.dealValue),rate=Number(b.commissionRate||0),amount=Number(b.commissionAmount||0),paid=Number(b.commissionPaid||0),share=Number(b.coBrokerShare||0),gst=Number(b.gstAmount||0),tds=Number(b.tdsDeducted||0);
    if(!cleanString(b.transactionDate,10)||!cleanString(b.propertyTitle,180)||!cleanString(b.propertyAddress,250)||!cleanString(b.city,100)||(!cleanString(b.buyerName,120)&&!cleanString(b.sellerName,120))) return fail("Complete the date, property, city and at least one buyer/seller.");
    if(!Number.isFinite(deal)||deal<0||!Number.isFinite(rate)||rate<0||rate>100||!Number.isFinite(amount)||amount<0||!Number.isFinite(paid)||paid<0||paid>amount||!Number.isFinite(share)||share<0||!Number.isFinite(gst)||gst<0||!Number.isFinite(tds)||tds<0) return fail("Check the deal value, commission and payment amounts.");
    const propertyId=cleanString(b.propertyId,80);
    if(propertyId && !await env.DB.prepare("SELECT id FROM properties WHERE id=? AND user_id=?").bind(propertyId,user.id).first()) return fail("Selected property was not found in your account.",404);
    const result=await env.DB.prepare(`UPDATE transactions SET property_id=?,transaction_ref=?,transaction_date=?,transaction_type=?,property_type=?,property_title=?,property_address=?,locality=?,city=?,state=?,pincode=?,buyer_name=?,buyer_phone=?,buyer_email=?,seller_name=?,seller_phone=?,seller_email=?,deal_value=?,commission_rate=?,commission_amount=?,commission_status=?,commission_paid=?,commission_paid_date=?,commission_invoice_no=?,commission_invoice_date=?,gst_amount=?,tds_deducted=?,broker_side=?,payment_method=?,payment_reference=?,transaction_status=?,lead_source=?,co_broker_name=?,co_broker_share=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?`)
      .bind(propertyId||null,cleanString(b.transactionRef,60),cleanString(b.transactionDate,10),cleanString(b.transactionType,30),cleanString(b.propertyType,60),cleanString(b.propertyTitle,180),cleanString(b.propertyAddress,250),cleanString(b.locality,120),cleanString(b.city,100),cleanString(b.state,100),cleanString(b.pincode,12),cleanString(b.buyerName,120),cleanString(b.buyerPhone,30),cleanString(b.buyerEmail,190),cleanString(b.sellerName,120),cleanString(b.sellerPhone,30),cleanString(b.sellerEmail,190),deal,rate,amount,cleanString(b.commissionStatus,30),paid,cleanString(b.commissionPaidDate,10),cleanString(b.commissionInvoiceNo,80),cleanString(b.commissionInvoiceDate,10),gst,tds,cleanString(b.brokerSide,20),cleanString(b.paymentMethod,50),cleanString(b.paymentReference,100),cleanString(b.transactionStatus,30),cleanString(b.leadSource,80),cleanString(b.coBrokerName,120),share,cleanString(b.notes,2000),transactionMatch[1],user.id).run();
    return result.meta.changes?json({ok:true}):fail("Transaction not found.",404);
  }
  if(transactionMatch && method==="DELETE") {
    const result=await env.DB.prepare("DELETE FROM transactions WHERE id=? AND user_id=?").bind(transactionMatch[1],user.id).run();
    return result.meta.changes?json({ok:true}):fail("Transaction not found.",404);
  }


  if (path === "/api/generate" && method === "POST") {
    const usage=await getUsage(env,user);
    if (usage.limit !== null && usage.used >= usage.limit) return fail(`You have used your ${usage.limit} free generations for this month. Upgrade your plan to continue.`,429);
    const b=await request.json().catch(()=>null); if(!b) return fail("Invalid property details.");
    const required=["title","bhk","location","city","priceValue","priceUnit","carpetArea","brokerName","brokerPhone"];
    for(const k of required) if(!cleanString(b[k],500)) return fail(`Please complete ${k}.`);
    if(!env.OPENAI_API_KEY) return fail("OpenAI API key is not configured in Cloudflare Worker secrets.",503);
    const systemPrompt=`You are a real estate copywriter specializing in the Indian real estate market. Use Indian currency units (Lakhs and Crores), never millions or billions. Highlight carpet area and RERA details accurately. Never claim RERA verification, legal approval, guaranteed returns, or Vastu compliance unless the user explicitly supplied that information. Use clear, high-converting, truthful copy.`;
    const userPrompt=`Create a localized marketing kit for this property:
Property: ${cleanString(b.bhk,20)} BHK in ${cleanString(b.title,180)}
Location: ${cleanString(b.location,120)}, ${cleanString(b.city,100)}
Price: ₹${cleanString(b.priceValue,30)} ${cleanString(b.priceUnit,10)}
Carpet area: ${cleanString(b.carpetArea,30)} sq.ft.
RERA ID supplied by user: ${cleanString(b.reraNumber,100)||"Not provided"}
Vastu compliance supplied by user: ${b.vastuCompliant?"Yes":"Not specified"}
Amenities: ${cleanString(b.amenities,1000)}
Broker: ${cleanString(b.brokerName,100)} (${cleanString(b.brokerPhone,30)})
Return a JSON object with exactly these string fields:
whatsappText: WhatsApp-ready copy using *bold*, restrained emojis, bullets and CTA.
socialCaption: Instagram/Facebook caption with relevant Indian real estate hashtags.
reelsScript: 30-second Hinglish script with [Visual Action] and [Audio/Dialogue] markers.`;
    const aiResponse=await fetch("https://api.openai.com/v1/chat/completions",{
      method:"POST",headers:{"content-type":"application/json","authorization":`Bearer ${env.OPENAI_API_KEY}`},
      body:JSON.stringify({model:"gpt-4o-mini",messages:[{role:"system",content:systemPrompt},{role:"user",content:userPrompt}],response_format:{type:"json_object"},temperature:0.7})
    });
    const aiData=await aiResponse.json().catch(()=>({}));
    if(!aiResponse.ok || aiData.error) return fail(aiData.error?.message || "AI generation failed. Please try again.",502);
    let content;
    try { content=JSON.parse(aiData.choices?.[0]?.message?.content || "{}"); } catch { return fail("AI returned an unreadable response. Please try again.",502); }
    for(const k of ["whatsappText","socialCaption","reelsScript"]) if(typeof content[k]!=="string") return fail("AI response was incomplete. Please try again.",502);
    const campaignId=uid();
    await env.DB.prepare("INSERT INTO campaigns(id,user_id,property_id,property_title,whatsapp_text,social_caption,reels_script) VALUES(?,?,?,?,?,?,?)")
      .bind(campaignId,user.id,cleanString(b.propertyId,80)||null,cleanString(b.title,180),content.whatsappText,content.socialCaption,content.reelsScript).run();
    await saveUsage(env,user);
    return json({...content,campaignId,usage:await getUsage(env,user)});
  }

  if (path === "/api/campaigns" && method === "GET") {
    const rows=await env.DB.prepare("SELECT id,property_title,created_at FROM campaigns WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return json({campaigns:rows.results});
  }
  const campaignMatch=path.match(/^\/api\/campaigns\/([a-f0-9-]+)$/i);
  if(campaignMatch && method==="GET") {
    const c=await env.DB.prepare("SELECT * FROM campaigns WHERE id=? AND user_id=?").bind(campaignMatch[1],user.id).first();
    return c?json({campaign:c}):fail("Campaign not found.",404);
  }
  if(campaignMatch && method==="DELETE") {
    await env.DB.prepare("DELETE FROM campaigns WHERE id=? AND user_id=?").bind(campaignMatch[1],user.id).run();
    return json({ok:true});
  }

  if(path === "/api/admin/users" && method==="GET") {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    const rows=await env.DB.prepare("SELECT id,name,email,role,plan,created_at FROM users ORDER BY created_at DESC LIMIT 500").all();
    return json({users:rows.results});
  }
  const adminUserMatch=path.match(/^\/api\/admin\/users\/([a-f0-9-]+)$/i);
  if(adminUserMatch && method==="PATCH") {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    const b=await request.json().catch(()=>null);
    if(!b || !["free","pro"].includes(b.plan) || !["user","admin"].includes(b.role)) return fail("Invalid account settings.");
    await env.DB.prepare("UPDATE users SET plan=?,role=? WHERE id=?").bind(b.plan,b.role,adminUserMatch[1]).run();
    return json({ok:true});
  }

  return fail("API route not found.",404);
}

export default {
  async fetch(request, env, ctx) {
    const url=new URL(request.url);
    if(url.pathname.startsWith("/api/")) {
      if(request.method==="OPTIONS") return new Response(null,{status:204,headers:{
        "access-control-allow-origin":env.APP_ORIGIN || url.origin,
        "access-control-allow-methods":"GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "access-control-allow-headers":"content-type",
        "access-control-allow-credentials":"true"
      }});
      try {
        const response=await handleApi(request,env,ctx);
        const headers=new Headers(response.headers);
        headers.set("x-content-type-options","nosniff");
        headers.set("referrer-policy","strict-origin-when-cross-origin");
        headers.set("cache-control","no-store");
        return new Response(response.body,{status:response.status,headers});
      } catch(err) {
        console.error("AgentGrow API error:",err);
        return fail("A server error occurred. Please try again. If the problem continues, contact support.",500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};

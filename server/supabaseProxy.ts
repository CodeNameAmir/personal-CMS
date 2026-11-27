export interface SupabaseServerConfig {
  supabaseUrl: string;
  supabasePublishableKey: string;
  supabaseSecretKey: string;
  supabaseConfigured: boolean;
}

export class BffError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function getSupabaseServerConfig(): SupabaseServerConfig {
  const supabaseUrl = (process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '').trim();
  const supabasePublishableKey = (
    process.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    ''
  ).trim();
  const supabaseSecretKey = (
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    ''
  ).trim();

  return {
    supabaseUrl,
    supabasePublishableKey,
    supabaseSecretKey,
    supabaseConfigured: Boolean(supabaseUrl && supabasePublishableKey),
  };
}

const SAFE_VALIDATION_MESSAGES = [
  'Username must be between',
  'Username may only contain',
  'Username is already registered.',
  'Password must be between',
  'Invalid username or password.',
  'New password must be between',
  'Current password is incorrect.',
  'Search query is too long',
  'Too many filter tags',
  'Too many tags per log',
  'A log cannot have more than',
  'Category name must be between',
  'Category color must be a valid',
  'Category already exists.',
  'Category not found',
  'Category not found or access denied.',
  'Tag name is required.',
  'Tag color must be a valid',
  'Tag already exists.',
  'Tag not found.',
  'Log message must be between',
  'Log not found.',
  'Bulk action is limited to',
  'Unsupported bulk action.',
  'Import records must be a JSON array.',
  'Import is limited to',
  'Import payload exceeds',
  'Token name must be between',
  'Maximum of 25 active API tokens',
];

export function mapSupabaseRpcError(
  status: number,
  body: { message?: string; code?: string } | null
): BffError {
  const msg = typeof body?.message === 'string' ? body.message : '';
  const code = typeof body?.code === 'string' ? body.code : '';

  if (msg.includes('RATE_LIMITED:')) {
    const clean = msg.replace(/^.*RATE_LIMITED:\s*/i, '').trim() || 'Too many requests. Please try again later.';
    return new BffError(clean, 429, 'RATE_LIMITED');
  }

  if (msg.includes('UNAUTHORIZED:')) {
    const clean = msg.replace(/^.*UNAUTHORIZED:\s*/i, '').trim() || 'Session expired or invalid.';
    return new BffError(clean, 401, 'UNAUTHORIZED');
  }

  if (
    code === 'PGRST202' ||
    code === 'PGRST205' ||
    code === '42P01' ||
    code === '42883' ||
    msg.includes('Could not find the function') ||
    msg.includes('Could not find the table') ||
    msg.includes('does not exist')
  ) {
    return new BffError(
      'Supabase database schema is not initialized or migrated yet. Run the SQL schema/migration in your Supabase SQL Editor.',
      400,
      'SCHEMA_MISSING'
    );
  }

  for (const prefix of SAFE_VALIDATION_MESSAGES) {
    if (msg.startsWith(prefix)) {
      return new BffError(msg, 400, 'VALIDATION_ERROR');
    }
  }

  if (status >= 500) {
    return new BffError('Database service temporarily unavailable.', 502, 'UPSTREAM_ERROR');
  }

  return new BffError('Request could not be completed.', 400, 'BAD_REQUEST');
}

export async function callSupabaseRpc<T>(
  fn: string,
  params: Record<string, unknown>,
  options: { useServiceRole?: boolean } = {}
): Promise<T> {
  const cfg = getSupabaseServerConfig();
  if (!cfg.supabaseConfigured) {
    throw new BffError(
      'Supabase environment variables (SUPABASE_URL / SUPABASE_PUBLISHABLE_KEY) are not configured yet.',
      503,
      'SUPABASE_NOT_CONFIGURED'
    );
  }

  const key = options.useServiceRole && cfg.supabaseSecretKey ? cfg.supabaseSecretKey : cfg.supabasePublishableKey;
  const endpoint = `${cfg.supabaseUrl.replace(/\/+$/, '')}/rest/v1/rpc/${encodeURIComponent(fn)}`;

  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new BffError('Unable to reach database service.', 502, 'UPSTREAM_UNREACHABLE');
  }

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const errObj = data && typeof data === 'object' ? (data as { message?: string; code?: string }) : null;
    throw mapSupabaseRpcError(res.status, errObj);
  }

  return data as T;
}

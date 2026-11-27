export type ThemeId = 'dark' | 'midnight' | 'light';

export type Language = 'en' | 'fa';

export type TagMatchMode = 'any' | 'all';

export interface Category {
  id: string;
  name: string;
  color: string;
  created_at: string;
  log_count?: number;
}

export interface Tag {
  id: string;
  name: string;
  color: string;
  created_at?: string;
  usage_count?: number;
}

export interface LogEntry {
  id: string;
  message: string;
  category_id: string | null;
  category_name: string;
  category_color: string;
  tags: Tag[];
  pinned: boolean;
  created_at: string;
  updated_at: string;
}

export interface LogFilters {
  q: string;
  categoryId: string;
  selectedTags: string[];
  tagMatchMode: TagMatchMode;
  dateFrom: string;
  pinnedOnly: boolean;
}

export interface WorkspaceQuery extends LogFilters {
  page: number;
  pageSize: number;
}

export interface CategoryStat {
  category_id: string;
  category_name: string;
  category_color: string;
  count: number;
}

export interface TagStat {
  tag_id: string;
  tag_name: string;
  tag_color: string;
  count: number;
}

export interface DayStat {
  day: string;
  count: number;
}

export interface LogStats {
  total_logs: number;
  pinned_logs: number;
  total_categories: number;
  total_tags: number;
  by_category: CategoryStat[];
  by_tag: TagStat[];
  by_day: DayStat[];
}

export interface ImportResult {
  imported: number;
  skipped: number;
  failed: number;
  errors: string[];
}

export interface UserSession {
  id: string;
  username: string;
}

export interface AppConfig {
  bffEnabled: boolean;
  supabaseUrl: string;
  supabasePublishableKey: string;
  supabaseConfigured: boolean;
}

export interface ApiTokenRecord {
  id: string;
  name: string;
  token_prefix: string;
  last_used_at: string | null;
  created_at: string;
}

export interface CreatedApiToken extends ApiTokenRecord {
  raw_token: string;
}

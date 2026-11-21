import React from 'react';
import {
  BarChart3,
  Cloud,
  Database,
  FileText,
  FolderPlus,
  Hash,
  Paperclip,
  Pencil,
  Pin,
  Plus,
  ScrollText,
  X,
} from 'lucide-react';
import { getTranslator } from '../i18n/translations';
import type { Category, DbMode, Language, LogFilters, Tag } from '../types/logbook';

interface SidebarProps {
  lang: Language;
  activeTab: 'logs' | 'stats';
  onSelectTab: (tab: 'logs' | 'stats') => void;
  dbMode: DbMode;
  categories: Category[];
  tags: Tag[];
  filters: LogFilters;
  totalLogsCount: number;
  pinnedCount: number;
  filesCount: number;
  onFilterChange: (patch: Partial<LogFilters>) => void;
  onToggleTagFilter: (tagName: string) => void;
  onOpenNewCategory: () => void;
  onEditCategory: (cat: Category) => void;
  onOpenNewTag: () => void;
  onEditTag: (tag: Tag) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  lang,
  activeTab,
  onSelectTab,
  dbMode,
  categories,
  tags,
  filters,
  totalLogsCount,
  pinnedCount,
  filesCount,
  onFilterChange,
  onToggleTagFilter,
  onOpenNewCategory,
  onEditCategory,
  onOpenNewTag,
  onEditTag,
  mobileOpen,
  onCloseMobile,
}) => {
  const t = getTranslator(lang);

  const isAllView =
    activeTab === 'logs' &&
    !filters.pinnedOnly &&
    !filters.hasFileOnly &&
    !filters.categoryId &&
    filters.selectedTags.length === 0;

  const content = (
    <div className="flex flex-col h-full w-[256px] bg-[var(--bg-surface)] border-e border-[var(--border-hairline)] select-none">
      {/* Brand + storage indicator */}
      <div className="px-4 py-4 border-b border-[var(--border-hairline)] flex items-center justify-between">
        <div>
          <div className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
            {t('appName')}
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
            {dbMode === 'supabase' ? (
              <Cloud className="w-3.5 h-3.5 shrink-0" />
            ) : (
              <Database className="w-3.5 h-3.5 shrink-0" />
            )}
            <span>{dbMode === 'supabase' ? t('supabasePostgresLabel') : t('localSqlite')}</span>
          </div>
        </div>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label={t('closeNavigation')}
          className="lg:hidden p-1.5 rounded-md text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {/* Primary views */}
        <div>
          <div className="px-2 mb-1.5 text-xs font-medium text-[var(--text-muted)]">
            {t('workspace')}
          </div>
          <nav className="space-y-0.5" aria-label={t('workspace')}>
            <button
              type="button"
              onClick={() => {
                onSelectTab('logs');
                onFilterChange({
                  categoryId: '',
                  selectedTags: [],
                  pinnedOnly: false,
                  hasFileOnly: false,
                });
                onCloseMobile();
              }}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-sm transition-colors ${
                isAllView
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] font-medium'
                  : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <ScrollText className="w-4 h-4 shrink-0" />
                <span>{t('allLogs')}</span>
              </span>
              <span className="text-xs font-mono tabular-nums text-[var(--text-muted)]">
                {totalLogsCount}
              </span>
            </button>

            <button
              type="button"
              onClick={() => {
                onSelectTab('logs');
                onFilterChange({ pinnedOnly: !filters.pinnedOnly, hasFileOnly: false });
                onCloseMobile();
              }}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-sm transition-colors ${
                activeTab === 'logs' && filters.pinnedOnly
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] font-medium'
                  : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Pin className="w-4 h-4 shrink-0 text-[var(--pin-accent)]" />
                <span>{t('pinned')}</span>
              </span>
              <span className="text-xs font-mono tabular-nums text-[var(--text-muted)]">
                {pinnedCount}
              </span>
            </button>

            <button
              type="button"
              onClick={() => {
                onSelectTab('logs');
                onFilterChange({ hasFileOnly: !filters.hasFileOnly, pinnedOnly: false });
                onCloseMobile();
              }}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-sm transition-colors ${
                activeTab === 'logs' && filters.hasFileOnly
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] font-medium'
                  : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Paperclip className="w-4 h-4 shrink-0" />
                <span>{t('withAttachments')}</span>
              </span>
              <span className="text-xs font-mono tabular-nums text-[var(--text-muted)]">
                {filesCount}
              </span>
            </button>

            <button
              type="button"
              onClick={() => {
                onSelectTab('stats');
                onCloseMobile();
              }}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-sm transition-colors ${
                activeTab === 'stats'
                  ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] font-medium'
                  : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <BarChart3 className="w-4 h-4 shrink-0" />
                <span>{t('statistics')}</span>
              </span>
            </button>
          </nav>
        </div>

        {/* Categories */}
        <div>
          <div className="px-2 mb-1.5 flex items-center justify-between">
            <span className="text-xs font-medium text-[var(--text-muted)]">{t('categories')}</span>
            <button
              type="button"
              onClick={onOpenNewCategory}
              aria-label={t('addCategory')}
              title={t('addCategory')}
              className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <FolderPlus className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="space-y-0.5">
            {categories.length === 0 ? (
              <div className="px-2.5 py-2 text-xs text-[var(--text-muted)]">{t('noCategoriesYet')}</div>
            ) : (
              categories.map((cat) => {
                const active = activeTab === 'logs' && filters.categoryId === cat.id;
                return (
                  <div
                    key={cat.id}
                    className={`group flex items-center justify-between rounded-lg transition-colors ${
                      active
                        ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                        : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        onSelectTab('logs');
                        onFilterChange({ categoryId: active ? '' : cat.id });
                        onCloseMobile();
                      }}
                      className="flex-1 flex items-center gap-2.5 px-2.5 py-1.5 text-sm text-start min-w-0"
                    >
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ backgroundColor: cat.color }}
                      />
                      <span className={`truncate ${active ? 'font-medium' : ''}`}>{cat.name}</span>
                    </button>
                    <div className="flex items-center gap-1 pe-2">
                      <button
                        type="button"
                        onClick={() => onEditCategory(cat)}
                        aria-label={`${t('editCategory')} ${cat.name}`}
                        className="opacity-0 group-hover:opacity-100 focus:opacity-100 p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-opacity"
                      >
                        <Pencil className="w-3 h-3" />
                      </button>
                      <span className="text-xs font-mono tabular-nums text-[var(--text-muted)] min-w-[18px] text-end">
                        {cat.log_count ?? 0}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Tags */}
        <div>
          <div className="px-2 mb-1.5 flex items-center justify-between">
            <span className="text-xs font-medium text-[var(--text-muted)]">{t('tags')}</span>
            <button
              type="button"
              onClick={onOpenNewTag}
              aria-label={t('addTag')}
              title={t('addTag')}
              className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
            </button>
          </div>

          {filters.selectedTags.length > 1 && (
            <div className="px-2 mb-2 flex items-center justify-between text-xs">
              <span className="text-[var(--text-muted)]">{t('matchMode')}</span>
              <div className="flex items-center gap-1 p-0.5 rounded bg-[var(--bg-canvas)] border border-[var(--border-hairline)]">
                <button
                  type="button"
                  onClick={() => onFilterChange({ tagMatchMode: 'any' })}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    filters.tagMatchMode === 'any'
                      ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {t('matchAny')}
                </button>
                <button
                  type="button"
                  onClick={() => onFilterChange({ tagMatchMode: 'all' })}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    filters.tagMatchMode === 'all'
                      ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {t('matchAll')}
                </button>
              </div>
            </div>
          )}

          <div className="space-y-0.5">
            {tags.length === 0 ? (
              <div className="px-2.5 py-2 text-xs text-[var(--text-muted)] flex items-center gap-2">
                <FileText className="w-3.5 h-3.5" />
                <span>{t('addTagsHint')}</span>
              </div>
            ) : (
              tags.map((tag) => {
                const selected = filters.selectedTags.includes(tag.name);
                return (
                  <div
                    key={tag.id}
                    className={`group flex items-center justify-between rounded-lg transition-colors ${
                      selected
                        ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                        : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        onSelectTab('logs');
                        onToggleTagFilter(tag.name);
                        onCloseMobile();
                      }}
                      className="flex-1 flex items-center gap-2 px-2.5 py-1.5 text-sm text-start min-w-0"
                    >
                      <Hash className="w-3.5 h-3.5 shrink-0" style={{ color: tag.color }} />
                      <span className={`truncate font-mono text-xs ${selected ? 'font-medium' : ''}`}>
                        {tag.name}
                      </span>
                    </button>
                    <div className="flex items-center gap-1 pe-2">
                      <button
                        type="button"
                        onClick={() => onEditTag(tag)}
                        aria-label={`${t('editTag')} ${tag.name}`}
                        className="opacity-0 group-hover:opacity-100 focus:opacity-100 p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-opacity"
                      >
                        <Pencil className="w-3 h-3" />
                      </button>
                      <span className="text-xs font-mono tabular-nums text-[var(--text-muted)] min-w-[18px] text-end">
                        {tag.usage_count ?? 0}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop persistent sidebar */}
      <aside className="hidden lg:block shrink-0">{content}</aside>

      {/* Mobile slide-over sidebar */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div className="fixed inset-0 bg-black/60" onClick={onCloseMobile} aria-hidden="true" />
          <div className="relative z-50 h-full">{content}</div>
        </div>
      )}
    </>
  );
};

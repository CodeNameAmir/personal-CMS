import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronDown,
  Download,
  FileUp,
  FolderPlus,
  Languages,
  LogOut,
  Menu,
  Pin,
  Plus,
  Search,
  Settings,
  X,
} from 'lucide-react';
import {
  ApiError,
  bulkLogsAction,
  changePassword,
  createCategory,
  createLog,
  createTag,
  deleteCategory,
  deleteLog,
  deleteTag,
  downloadExportLogs,
  fetchSupabaseSchema,
  fetchWorkspace,
  importLogs,
  logout,
  restoreSession,
  setUnauthorizedHandler,
  subscribeAuthEvents,
  togglePinLog,
  updateCategory,
  updateLog,
  updateTag,
} from './api/client';
import { AuthScreen } from './components/AuthScreen';
import { LogTable } from './components/LogTable';
import {
  AccountModal,
  ImportModal,
  LogDetailModal,
  LogEditorModal,
  TaxonomyModal,
} from './components/Modals';
import { Sidebar } from './components/Sidebar';
import { StatsView } from './components/StatsView';
import { getTranslator } from './i18n/translations';
import type {
  Category,
  ImportResult,
  Language,
  LogEntry,
  LogFilters,
  LogStats,
  Tag,
  ThemeId,
  UserSession,
} from './types/logbook';

const EMPTY_FILTERS: LogFilters = {
  q: '',
  categoryId: '',
  selectedTags: [],
  tagMatchMode: 'any',
  dateFrom: '',
  pinnedOnly: false,
};

interface ToastItem {
  id: number;
  message: string;
  kind: 'ok' | 'error' | 'info';
}

export default function App() {
  const [theme, setTheme] = useState<ThemeId>(() => {
    try {
      const saved = localStorage.getItem('logbook_theme') as ThemeId | null;
      if (saved === 'dark' || saved === 'midnight' || saved === 'light') return saved;
    } catch {
      // ignore
    }
    return 'dark';
  });

  const [lang, setLang] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem('logbook_lang') as Language | null;
      if (saved === 'en' || saved === 'fa') return saved;
    } catch {
      // ignore
    }
    return 'en';
  });

  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('logbook_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });

  const t = useMemo(() => getTranslator(lang), [lang]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('logbook_theme', theme);
    } catch {
      // ignore
    }
  }, [theme]);

  useEffect(() => {
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
    try {
      localStorage.setItem('logbook_lang', lang);
    } catch {
      // ignore
    }
  }, [lang]);

  const handleToggleSidebarCollapse = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('logbook_sidebar_collapsed', String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  const [user, setUser] = useState<UserSession | null>(null);
  const [restoringSession, setRestoringSession] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'logs' | 'stats'>('logs');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  const [categories, setCategories] = useState<Category[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [pagedLogs, setPagedLogs] = useState<LogEntry[]>([]);
  const [totalLogsCount, setTotalLogsCount] = useState<number>(0);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [loadingLogs, setLoadingLogs] = useState(false);

  const [filters, setFilters] = useState<LogFilters>(EMPTY_FILTERS);
  const [searchDraft, setSearchDraft] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const [dataMenuOpen, setDataMenuOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const [editingLog, setEditingLog] = useState<LogEntry | null | undefined>(undefined);
  const [detailLog, setDetailLog] = useState<LogEntry | null>(null);
  const [taxonomyModal, setTaxonomyModal] = useState<{
    kind: 'category' | 'tag';
    item: Category | Tag | null;
  } | null>(null);
  const [importModalFormat, setImportModalFormat] = useState<'json' | 'csv' | null>(null);
  const [accountModalOpen, setAccountModalOpen] = useState(false);
  const [supabaseSqlPrompt, setSupabaseSqlPrompt] = useState<string | null>(null);

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const pushToast = useCallback((message: string, kind: 'ok' | 'error' | 'info' = 'info') => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev, { id, message, kind }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id));
    }, 3200);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      setPagedLogs([]);
      setTotalLogsCount(0);
      setStats(null);
      setCategories([]);
      setTags([]);
      pushToast(getTranslator(lang)('sessionExpired'), 'error');
    });
  }, [pushToast, lang]);

  // Restore HttpOnly cookie session on page load & sync sign-out across tabs
  useEffect(() => {
    let active = true;
    restoreSession()
      .then((resumedUser) => {
        if (!active) return;
        setUser(resumedUser);
      })
      .finally(() => {
        if (active) setRestoringSession(false);
      });

    const unsubscribe = subscribeAuthEvents(() => {
      setUser(null);
      setPagedLogs([]);
      setTotalLogsCount(0);
      setStats(null);
      setCategories([]);
      setTags([]);
    });

    return () => {
      active = false;
      unsubscribe();
    };
  }, []);

  const handleApiError = useCallback(
    async (err: unknown, fallback: string) => {
      if (err instanceof ApiError && err.code === 'SCHEMA_MISSING') {
        try {
          const res = await fetchSupabaseSchema();
          setSupabaseSqlPrompt(res.sql);
        } catch {
          // ignore
        }
      }
      pushToast(err instanceof Error ? err.message : fallback, 'error');
    },
    [pushToast]
  );

  const loadWorkspaceData = useCallback(async () => {
    if (!user) return;
    setLoadingLogs(true);
    try {
      const snapshot = await fetchWorkspace({
        ...filters,
        page,
        pageSize,
      });
      setCategories(snapshot.categories || []);
      setTags(snapshot.tags || []);
      setPagedLogs(snapshot.logs || []);
      setTotalLogsCount(snapshot.total_count ?? (snapshot.logs ? snapshot.logs.length : 0));
      setStats(snapshot.stats || null);
    } catch (err) {
      await handleApiError(err, 'Failed to load workspace data');
    } finally {
      setLoadingLogs(false);
    }
  }, [user, filters, page, pageSize, handleApiError]);

  useEffect(() => {
    if (user) {
      loadWorkspaceData();
    }
  }, [user, loadWorkspaceData]);

  // Clamp page if filtered total shrinks
  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(totalLogsCount / pageSize));
    if (page > maxPage) setPage(maxPage);
  }, [totalLogsCount, page, pageSize]);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => {
        if (prev.q === searchDraft) return prev;
        setPage(1);
        return { ...prev, q: searchDraft };
      });
    }, 180);
    return () => clearTimeout(timer);
  }, [searchDraft]);

  // Keyboard shortcuts: '/' focuses search, 'n' opens New Log when not typing
  useEffect(() => {
    if (!user) return;
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const inInput =
        target?.tagName === 'INPUT' ||
        target?.tagName === 'TEXTAREA' ||
        target?.tagName === 'SELECT' ||
        target?.isContentEditable;
      if (inInput) return;

      if (e.key === '/' || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key.toLowerCase() === 'n') {
        e.preventDefault();
        setEditingLog(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [user]);

  const handleFilterChange = (patch: Partial<LogFilters>) => {
    setPage(1);
    setSelectedIds([]);
    setFilters((prev) => ({ ...prev, ...patch }));
  };

  const handleToggleTagFilter = (tagName: string) => {
    setPage(1);
    setSelectedIds([]);
    setFilters((prev) => {
      const exists = prev.selectedTags.includes(tagName);
      return {
        ...prev,
        selectedTags: exists
          ? prev.selectedTags.filter((item) => item !== tagName)
          : [...prev.selectedTags, tagName],
      };
    });
  };

  const handleClearFilters = () => {
    setSearchDraft('');
    setPage(1);
    setSelectedIds([]);
    setFilters(EMPTY_FILTERS);
  };

  const hasActiveFilters = useMemo(() => {
    return Boolean(
      filters.q ||
        filters.categoryId ||
        filters.selectedTags.length > 0 ||
        filters.dateFrom ||
        filters.pinnedOnly
    );
  }, [filters]);

  const handleSaveLog = async (payload: {
    id?: string;
    message: string;
    category_id: string | null;
    tags: string[];
    pinned: boolean;
  }) => {
    try {
      if (payload.id) {
        await updateLog(payload.id, {
          message: payload.message,
          category_id: payload.category_id,
          tags: payload.tags,
          pinned: payload.pinned,
        });
      } else {
        await createLog({
          message: payload.message,
          category_id: payload.category_id,
          tags: payload.tags,
          pinned: payload.pinned,
        });
      }

      pushToast(payload.id ? t('logUpdated') : t('logAdded'), 'ok');
      if (!payload.id) setPage(1);
      await loadWorkspaceData();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'SCHEMA_MISSING') {
        try {
          const res = await fetchSupabaseSchema();
          setSupabaseSqlPrompt(res.sql);
        } catch {
          // ignore
        }
      }
      throw err;
    }
  };

  const handleTogglePin = async (log: LogEntry) => {
    try {
      await togglePinLog(log.id);
      await loadWorkspaceData();
      pushToast(log.pinned ? t('unpinnedToast') : t('pinnedToast'), 'ok');
    } catch (err) {
      await handleApiError(err, 'Failed to toggle pin');
    }
  };

  const handleDeleteLog = async (log: LogEntry) => {
    try {
      await deleteLog(log.id);
      setSelectedIds((prev) => prev.filter((id) => id !== log.id));
      await loadWorkspaceData();
      pushToast(t('logDeleted'), 'ok');
    } catch (err) {
      await handleApiError(err, 'Failed to delete log');
    }
  };

  const handleBulkAction = async (action: {
    type: 'pin' | 'unpin' | 'delete' | 'category' | 'add_tag';
    category_id?: string | null;
    tag?: string;
  }) => {
    try {
      const res = await bulkLogsAction({ ids: selectedIds, ...action });
      setSelectedIds([]);
      await loadWorkspaceData();
      pushToast(`${t('bulkUpdatedPrefix')} ${res.affected}`, 'ok');
    } catch (err) {
      await handleApiError(err, 'Bulk update failed');
    }
  };

  const handleCopyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      pushToast(t('copiedClipboard'), 'ok');
    } catch {
      pushToast(t('unableCopy'), 'error');
    }
  };

  const handleSaveTaxonomy = async (name: string, color: string, id?: string) => {
    if (!taxonomyModal) return;
    try {
      if (taxonomyModal.kind === 'category') {
        if (id) await updateCategory(id, name, color);
        else await createCategory(name, color);
      } else {
        if (id) await updateTag(id, name, color);
        else await createTag(name, color);
      }
      pushToast(taxonomyModal.kind === 'category' ? t('categorySaved') : t('tagSaved'), 'ok');
      await loadWorkspaceData();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'SCHEMA_MISSING') {
        try {
          const res = await fetchSupabaseSchema();
          setSupabaseSqlPrompt(res.sql);
        } catch {
          // ignore
        }
      }
      throw err;
    }
  };

  const handleDeleteTaxonomy = async (id: string) => {
    if (!taxonomyModal) return;
    if (taxonomyModal.kind === 'category') {
      await deleteCategory(id);
      if (filters.categoryId === id) {
        setFilters((prev) => ({ ...prev, categoryId: '' }));
      }
    } else {
      const targetTag = tags.find((item) => item.id === id);
      await deleteTag(id);
      if (targetTag && filters.selectedTags.includes(targetTag.name)) {
        setFilters((prev) => ({
          ...prev,
          selectedTags: prev.selectedTags.filter((item) => item !== targetTag.name),
        }));
      }
    }
    pushToast(taxonomyModal.kind === 'category' ? t('categoryDeleted') : t('tagDeleted'), 'ok');
    await loadWorkspaceData();
  };

  const handleImport = async (
    format: 'json' | 'csv',
    input: { file?: File; content?: string }
  ): Promise<ImportResult> => {
    const res = await importLogs(format, input);
    await loadWorkspaceData();
    pushToast(`${t('importedToastPrefix')} ${res.imported}`, 'ok');
    return res;
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setDataMenuOpen(false);
    try {
      await downloadExportLogs(format, categories, filters);
      pushToast(`${t('exportedLabel')} ${format.toUpperCase()}`, 'ok');
    } catch (err) {
      await handleApiError(err, 'Export failed');
    }
  };

  const handleLogout = async () => {
    setUserMenuOpen(false);
    await logout();
    setUser(null);
    setPagedLogs([]);
    setTotalLogsCount(0);
    setStats(null);
    setCategories([]);
    setTags([]);
    setFilters(EMPTY_FILTERS);
    setSearchDraft('');
    setSelectedIds([]);
  };

  if (restoringSession) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--bg-canvas)] text-[var(--text-secondary)] text-sm">
        {t('pleaseWait')}
      </div>
    );
  }

  if (!user) {
    return (
      <AuthScreen
        theme={theme}
        lang={lang}
        onChangeTheme={setTheme}
        onChangeLang={setLang}
        onAuthenticated={(loggedInUser) => {
          setUser(loggedInUser);
          setActiveTab('logs');
          setFilters(EMPTY_FILTERS);
          setSearchDraft('');
          setPage(1);
        }}
      />
    );
  }

  return (
    <div className="min-h-screen flex bg-[var(--bg-canvas)] text-[var(--text-primary)]">
      <Sidebar
        lang={lang}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        categories={categories}
        tags={tags}
        filters={filters}
        totalLogsCount={stats?.total_logs ?? totalLogsCount}
        pinnedCount={stats?.pinned_logs ?? 0}
        onFilterChange={handleFilterChange}
        onToggleTagFilter={handleToggleTagFilter}
        onOpenNewCategory={() => setTaxonomyModal({ kind: 'category', item: null })}
        onEditCategory={(cat) => setTaxonomyModal({ kind: 'category', item: cat })}
        onOpenNewTag={() => setTaxonomyModal({ kind: 'tag', item: null })}
        onEditTag={(tag) => setTaxonomyModal({ kind: 'tag', item: tag })}
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleSidebarCollapse}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top bar */}
        <header className="sticky top-0 z-20 px-4 sm:px-6 py-3.5 border-b border-[var(--border-hairline)] bg-[var(--bg-surface)] flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileSidebarOpen(true)}
              aria-label={t('openNavigation')}
              className="lg:hidden p-2 rounded-lg border border-[var(--border-hairline)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            >
              <Menu className="w-4 h-4" />
            </button>
            <h1 className="text-base font-semibold tracking-tight text-[var(--text-primary)] truncate">
              {activeTab === 'stats'
                ? t('statistics')
                : filters.pinnedOnly
                  ? t('pinnedLogs')
                  : filters.categoryId
                    ? categories.find((c) => c.id === filters.categoryId)?.name || t('categoryLabel')
                    : t('allLogs')}
            </h1>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setEditingLog(null)}
              className="inline-flex items-center gap-1.5 px-3 sm:px-3.5 py-2 rounded-lg text-xs font-medium bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors whitespace-nowrap shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span className="sm:hidden">{t('addShort')}</span>
              <span className="hidden sm:inline">{t('addLog')}</span>
            </button>

            <button
              type="button"
              onClick={() => setTaxonomyModal({ kind: 'category', item: null })}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap shrink-0"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              <span>{t('categoryBtn')}</span>
            </button>

            {/* Quick bilingual toggle */}
            <button
              type="button"
              onClick={() => setLang((prev) => (prev === 'en' ? 'fa' : 'en'))}
              aria-label={t('languageLabel')}
              className="inline-flex items-center gap-1 px-2.5 py-2 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap shrink-0"
            >
              <Languages className="w-3.5 h-3.5" />
              <span>{lang === 'en' ? 'FA' : 'EN'}</span>
            </button>

            {/* Import / Export menu */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setUserMenuOpen(false);
                  setDataMenuOpen((v) => !v);
                }}
                aria-expanded={dataMenuOpen}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap shrink-0"
              >
                <span>{t('dataBtn')}</span>
                <ChevronDown className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              </button>

              {dataMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-20"
                    onClick={() => setDataMenuOpen(false)}
                    aria-hidden="true"
                  />
                  <div className="absolute end-0 mt-1.5 z-30 w-44 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] py-1 shadow-lg">
                    <button
                      type="button"
                      onClick={() => {
                        setDataMenuOpen(false);
                        setImportModalFormat('json');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <FileUp className="w-3.5 h-3.5" />
                      <span>{t('importJson')}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDataMenuOpen(false);
                        setImportModalFormat('csv');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <FileUp className="w-3.5 h-3.5" />
                      <span>{t('importCsv')}</span>
                    </button>
                    <div className="my-1 border-t border-[var(--border-hairline)]" />
                    <button
                      type="button"
                      onClick={() => handleExport('json')}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>{t('exportJson')}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExport('csv')}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>{t('exportCsv')}</span>
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* User account menu */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setDataMenuOpen(false);
                  setUserMenuOpen((v) => !v);
                }}
                aria-expanded={userMenuOpen}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap shrink-0"
              >
                <span className="max-w-[90px] truncate">{user.username}</span>
                <ChevronDown className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              </button>

              {userMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-20"
                    onClick={() => setUserMenuOpen(false)}
                    aria-hidden="true"
                  />
                  <div className="absolute end-0 mt-1.5 z-30 w-48 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] py-1 shadow-lg">
                    <button
                      type="button"
                      onClick={() => {
                        setUserMenuOpen(false);
                        setAccountModalOpen(true);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <Settings className="w-3.5 h-3.5" />
                      <span>{t('settingsAndApi')}</span>
                    </button>
                    <div className="my-1 border-t border-[var(--border-hairline)]" />
                    <button
                      type="button"
                      onClick={handleLogout}
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400 hover:bg-red-500/10"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>{t('signOut')}</span>
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Main Workspace Content */}
        <main className="flex-1 p-4 sm:p-6 max-w-[1600px] w-full mx-auto space-y-4">
          {supabaseSqlPrompt && (
            <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div>
                <span className="font-semibold text-amber-300">{t('supabaseSqlHintTitle')}.</span>{' '}
                <span className="text-[var(--text-secondary)]">{t('supabaseSqlHintDesc')}</span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  await navigator.clipboard.writeText(supabaseSqlPrompt);
                  pushToast(t('copiedClipboard'), 'ok');
                }}
                className="px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-strong)] font-medium hover:bg-[var(--bg-hover)]"
              >
                {t('copySqlSchema')}
              </button>
            </div>
          )}

          {activeTab === 'logs' ? (
            <>
              {/* Filter Bar (No Log Levels!) */}
              <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3 flex flex-col lg:flex-row lg:items-center gap-2.5">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="w-4 h-4 absolute start-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
                  <input
                    ref={searchInputRef}
                    type="search"
                    maxLength={200}
                    value={searchDraft}
                    onChange={(e) => setSearchDraft(e.target.value)}
                    placeholder={t('searchPlaceholder')}
                    aria-label={t('searchPlaceholder')}
                    className="w-full ps-9 pe-3 py-2 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <select
                    aria-label={t('allCategories')}
                    value={filters.categoryId}
                    onChange={(e) => handleFilterChange({ categoryId: e.target.value })}
                    className="px-3 py-2 text-xs rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                  >
                    <option value="">{t('allCategories')}</option>
                    {categories.map((cat) => (
                      <option key={cat.id} value={cat.id}>
                        {cat.name}
                      </option>
                    ))}
                  </select>

                  <input
                    type="date"
                    dir="ltr"
                    aria-label="Filter from date"
                    value={filters.dateFrom}
                    onChange={(e) => handleFilterChange({ dateFrom: e.target.value })}
                    className="px-3 py-2 text-xs font-mono rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                  />

                  <button
                    type="button"
                    onClick={() => handleFilterChange({ pinnedOnly: !filters.pinnedOnly })}
                    className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
                      filters.pinnedOnly
                        ? 'border-[var(--pin-accent)] bg-[var(--pin-surface)] text-[var(--text-primary)]'
                        : 'border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    <Pin className="w-3.5 h-3.5" />
                    <span>{t('pinned')}</span>
                  </button>

                  {hasActiveFilters && (
                    <button
                      type="button"
                      onClick={handleClearFilters}
                      className="inline-flex items-center gap-1 px-2.5 py-2 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>{t('clear')}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Active Tag Filter Strip */}
              {filters.selectedTags.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 px-1 text-xs">
                  <span className="text-[var(--text-muted)]">{t('filteringByTags')}</span>
                  {filters.selectedTags.map((tagName) => (
                    <button
                      key={tagName}
                      type="button"
                      onClick={() => handleToggleTagFilter(tagName)}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-strong)] font-mono text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                    >
                      <span dir="ltr" className="inline-flex items-center">
                        <span className="text-[var(--accent)]">#</span>
                        <span>{tagName}</span>
                      </span>
                      <X className="w-3 h-3 text-[var(--text-muted)]" />
                    </button>
                  ))}
                  {filters.selectedTags.length > 1 && (
                    <button
                      type="button"
                      onClick={() =>
                        handleFilterChange({
                          tagMatchMode: filters.tagMatchMode === 'any' ? 'all' : 'any',
                        })
                      }
                      className="text-xs text-[var(--accent)] hover:underline ms-1"
                    >
                      {t('modeMatchPrefix')}{' '}
                      {filters.tagMatchMode === 'any' ? t('matchAny') : t('matchAll')}
                    </button>
                  )}
                </div>
              )}

              <LogTable
                lang={lang}
                logs={pagedLogs}
                loading={loadingLogs}
                totalLogs={totalLogsCount}
                page={page}
                pageSize={pageSize}
                categories={categories}
                selectedIds={selectedIds}
                onToggleSelect={(id) =>
                  setSelectedIds((prev) =>
                    prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
                  )
                }
                onToggleSelectAll={() => {
                  const allSelected =
                    pagedLogs.length > 0 && pagedLogs.every((l) => selectedIds.includes(l.id));
                  setSelectedIds(allSelected ? [] : pagedLogs.map((l) => l.id));
                }}
                onClearSelection={() => setSelectedIds([])}
                onBulkAction={handleBulkAction}
                onPageChange={setPage}
                onPageSizeChange={(size) => {
                  setPageSize(size);
                  setPage(1);
                }}
                onViewDetail={setDetailLog}
                onEditLog={setEditingLog}
                onTogglePin={handleTogglePin}
                onCopyMessage={handleCopyText}
                onDeleteLog={handleDeleteLog}
                onFilterCategory={(catId) =>
                  handleFilterChange({
                    categoryId: filters.categoryId === catId ? '' : catId,
                  })
                }
                onToggleTag={handleToggleTagFilter}
                onNewLog={() => setEditingLog(null)}
                hasActiveFilters={hasActiveFilters}
                onClearFilters={handleClearFilters}
              />
            </>
          ) : (
            <StatsView
              lang={lang}
              stats={stats}
              loading={loadingLogs}
              onFilterCategory={(catId) => {
                setActiveTab('logs');
                handleFilterChange({ categoryId: catId });
              }}
              onFilterTag={(tagName) => {
                setActiveTab('logs');
                handleFilterChange({ selectedTags: [tagName] });
              }}
            />
          )}
        </main>
      </div>

      {/* Modals */}
      {editingLog !== undefined && (
        <LogEditorModal
          lang={lang}
          log={editingLog}
          categories={categories}
          availableTags={tags}
          onClose={() => setEditingLog(undefined)}
          onSave={handleSaveLog}
        />
      )}

      {detailLog && (
        <LogDetailModal
          lang={lang}
          log={detailLog}
          onClose={() => setDetailLog(null)}
          onEdit={(l) => setEditingLog(l)}
          onTogglePin={async (l) => {
            await handleTogglePin(l);
            setDetailLog((prev) => (prev ? { ...prev, pinned: !prev.pinned } : null));
          }}
          onDelete={handleDeleteLog}
          onCopy={handleCopyText}
          onFilterTag={handleToggleTagFilter}
        />
      )}

      {taxonomyModal && (
        <TaxonomyModal
          lang={lang}
          kind={taxonomyModal.kind}
          item={taxonomyModal.item}
          onClose={() => setTaxonomyModal(null)}
          onSave={handleSaveTaxonomy}
          onDelete={handleDeleteTaxonomy}
        />
      )}

      {importModalFormat && (
        <ImportModal
          lang={lang}
          initialFormat={importModalFormat}
          onClose={() => setImportModalFormat(null)}
          onImport={handleImport}
        />
      )}

      {accountModalOpen && (
        <AccountModal
          lang={lang}
          onChangeLang={setLang}
          username={user.username}
          theme={theme}
          onChangeTheme={setTheme}
          onChangePassword={async (cur, next) => {
            await changePassword(cur, next);
          }}
          onWebhookSent={loadWorkspaceData}
          onNotify={pushToast}
          supabaseSql={supabaseSqlPrompt || undefined}
          onClose={() => setAccountModalOpen(false)}
        />
      )}

      {/* Toast stack */}
      <div className="fixed bottom-4 end-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((item) => (
          <div
            key={item.id}
            className={`pointer-events-auto px-4 py-2.5 rounded-lg border text-xs font-medium shadow-lg ${
              item.kind === 'error'
                ? 'bg-[var(--bg-elevated)] border-red-500/40 text-red-400'
                : item.kind === 'ok'
                  ? 'bg-[var(--bg-elevated)] border-emerald-500/40 text-emerald-400'
                  : 'bg-[var(--bg-elevated)] border-[var(--border-strong)] text-[var(--text-primary)]'
            }`}
          >
            {item.message}
          </div>
        ))}
      </div>
    </div>
  );
}

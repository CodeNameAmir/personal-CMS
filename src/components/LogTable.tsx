import React, { useState } from 'react';
import {
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Copy,
  FileText,
  MoreVertical,
  Pencil,
  Pin,
  PinOff,
  Plus,
  Square,
  Trash2,
} from 'lucide-react';
import { getTranslator } from '../i18n/translations';
import type { Category, Language, LogEntry } from '../types/logbook';
import { formatExactTime, formatRelativeTime } from '../utils/logFormatters';

interface LogTableProps {
  lang: Language;
  logs: LogEntry[];
  loading: boolean;
  totalLogs: number;
  page: number;
  pageSize: number;
  categories: Category[];
  selectedIds: string[];
  onToggleSelect: (id: string) => void;
  onToggleSelectAll: () => void;
  onClearSelection: () => void;
  onBulkAction: (action: {
    type: 'pin' | 'unpin' | 'delete' | 'category' | 'add_tag';
    category_id?: string | null;
    tag?: string;
  }) => Promise<void>;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  onViewDetail: (log: LogEntry) => void;
  onEditLog: (log: LogEntry) => void;
  onTogglePin: (log: LogEntry) => void;
  onCopyMessage: (message: string) => void;
  onDeleteLog: (log: LogEntry) => void;
  onFilterCategory: (categoryId: string) => void;
  onToggleTag: (tagName: string) => void;
  onNewLog: () => void;
  hasActiveFilters: boolean;
  onClearFilters: () => void;
}

export const LogTable: React.FC<LogTableProps> = ({
  lang,
  logs,
  loading,
  totalLogs,
  page,
  pageSize,
  categories,
  selectedIds,
  onToggleSelect,
  onToggleSelectAll,
  onClearSelection,
  onBulkAction,
  onPageChange,
  onPageSizeChange,
  onViewDetail,
  onEditLog,
  onTogglePin,
  onCopyMessage,
  onDeleteLog,
  onFilterCategory,
  onToggleTag,
  onNewLog,
  hasActiveFilters,
  onClearFilters,
}) => {
  const t = getTranslator(lang);
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [bulkTagInput, setBulkTagInput] = useState('');
  const [bulkCategory, setBulkCategory] = useState('');

  const totalPages = Math.max(1, Math.ceil(totalLogs / pageSize));
  const startIdx = totalLogs === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = totalLogs === 0 ? 0 : Math.min(page * pageSize, totalLogs);
  const allVisibleSelected = logs.length > 0 && logs.every((l) => selectedIds.includes(l.id));

  const renderPageNumbers = () => {
    const pages: Array<number | '...'> = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i += 1) pages.push(i);
    } else if (page <= 4) {
      pages.push(1, 2, 3, 4, 5, '...', totalPages);
    } else if (page >= totalPages - 3) {
      pages.push(1, '...', totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages);
    } else {
      pages.push(1, '...', page - 1, page, page + 1, '...', totalPages);
    }
    return pages;
  };

  return (
    <div className="space-y-3">
      {/* Bulk actions bar */}
      {selectedIds.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)]">
          <div className="flex items-center gap-3 text-sm">
            <span className="font-mono tabular-nums font-medium">
              {selectedIds.length} {t('selectedCount')}
            </span>
            <button
              type="button"
              onClick={onClearSelection}
              className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] underline"
            >
              {t('clear')}
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onBulkAction({ type: 'pin' })}
              className="px-2.5 py-1 text-xs font-medium rounded-md border border-[var(--border-hairline)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap"
            >
              {t('pin')}
            </button>
            <button
              type="button"
              onClick={() => onBulkAction({ type: 'unpin' })}
              className="px-2.5 py-1 text-xs font-medium rounded-md border border-[var(--border-hairline)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] transition-colors whitespace-nowrap"
            >
              {t('unpin')}
            </button>
            <select
              aria-label={t('moveCategory')}
              value={bulkCategory}
              onChange={(e) => {
                const val = e.target.value;
                setBulkCategory('');
                if (val) onBulkAction({ type: 'category', category_id: val === '__none__' ? null : val });
              }}
              className="px-2.5 py-1 text-xs rounded-md border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-primary)]"
            >
              <option value="">{t('moveCategory')}</option>
              {categories.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!bulkTagInput.trim()) return;
                onBulkAction({ type: 'add_tag', tag: bulkTagInput.trim() });
                setBulkTagInput('');
              }}
              className="flex items-center gap-1"
            >
              <input
                type="text"
                value={bulkTagInput}
                onChange={(e) => setBulkTagInput(e.target.value)}
                placeholder={t('addTagPlaceholder')}
                aria-label={t('addTag')}
                className="w-28 px-2.5 py-1 text-xs rounded-md border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-primary)]"
              />
              <button
                type="submit"
                className="px-2.5 py-1 text-xs font-medium rounded-md border border-[var(--border-hairline)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)]"
              >
                {t('apply')}
              </button>
            </form>
            <button
              type="button"
              onClick={() => onBulkAction({ type: 'delete' })}
              className="px-2.5 py-1 text-xs font-medium rounded-md border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors whitespace-nowrap"
            >
              {t('delete')}
            </button>
          </div>
        </div>
      )}

      {/* Main data container */}
      <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] overflow-hidden">
        {loading ? (
          <div className="divide-y divide-[var(--border-hairline)]">
            {Array.from({ length: 5 }).map((_, idx) => (
              <div key={idx} className="px-4 py-3.5 flex items-center gap-4 animate-pulse">
                <div className="w-4 h-4 rounded bg-[var(--bg-elevated)]" />
                <div className="w-24 h-4 rounded bg-[var(--bg-elevated)]" />
                <div className="flex-1 h-4 rounded bg-[var(--bg-elevated)]" />
                <div className="w-20 h-4 rounded bg-[var(--bg-elevated)]" />
              </div>
            ))}
          </div>
        ) : logs.length === 0 ? (
          <div className="py-16 px-6 text-center">
            <FileText className="w-10 h-10 mx-auto text-[var(--text-muted)] opacity-50 mb-3" />
            <p className="text-sm font-medium text-[var(--text-primary)]">
              {hasActiveFilters ? t('noLogsMatch') : t('noLogsYet')}
            </p>
            <p className="mt-1 text-xs text-[var(--text-secondary)]">
              {hasActiveFilters ? t('noLogsMatchSub') : t('noLogsYetSub')}
            </p>
            <div className="mt-5 flex items-center justify-center gap-2">
              {hasActiveFilters ? (
                <button
                  type="button"
                  onClick={onClearFilters}
                  className="px-4 py-2 text-xs font-medium rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] transition-colors"
                >
                  {t('clearFilters')}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={onNewLog}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{t('addFirstLog')}</span>
                </button>
              )}
            </div>
          </div>
        ) : (
          <>
            {/* Desktop table */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full border-collapse text-start">
                <thead>
                  <tr className="border-b border-[var(--border-strong)] bg-[var(--bg-elevated)] text-xs font-medium text-[var(--text-secondary)]">
                    <th className="w-10 py-3 ps-4 pe-2 text-start">
                      <button
                        type="button"
                        onClick={onToggleSelectAll}
                        aria-label={allVisibleSelected ? t('clear') : t('selectedCount')}
                        className="text-[var(--text-muted)] hover:text-[var(--text-primary)] flex items-center"
                      >
                        {allVisibleSelected ? (
                          <CheckSquare className="w-4 h-4 text-[var(--accent)]" />
                        ) : (
                          <Square className="w-4 h-4" />
                        )}
                      </button>
                    </th>
                    <th className="w-10 py-3 px-2" aria-label={t('pinned')} />
                    <th className="w-36 py-3 px-3 text-start">{t('colCategory')}</th>
                    <th className="py-3 px-3 text-start">{t('colMessage')}</th>
                    <th className="w-56 py-3 px-3 text-start">{t('colTags')}</th>
                    <th className="w-36 py-3 px-3 text-end">{t('colTime')}</th>
                    <th className="w-16 py-3 ps-2 pe-4 text-end">{t('colActions')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-hairline)] text-sm">
                  {logs.map((log) => {
                    const isSelected = selectedIds.includes(log.id);
                    const isMenuOpen = openMenuId === log.id;
                    return (
                      <tr
                        key={log.id}
                        className={`transition-colors ${
                          log.pinned
                            ? 'bg-[var(--pin-surface)] hover:bg-[var(--bg-hover)]'
                            : 'hover:bg-[var(--bg-hover)]'
                        }`}
                      >
                        <td className="py-2.5 ps-4 pe-2 align-middle">
                          <button
                            type="button"
                            onClick={() => onToggleSelect(log.id)}
                            aria-label={`Select log ${log.message.slice(0, 24)}`}
                            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] flex items-center"
                          >
                            {isSelected ? (
                              <CheckSquare className="w-4 h-4 text-[var(--accent)]" />
                            ) : (
                              <Square className="w-4 h-4" />
                            )}
                          </button>
                        </td>

                        <td className="py-2.5 px-2 align-middle">
                          <button
                            type="button"
                            onClick={() => onTogglePin(log)}
                            aria-label={log.pinned ? t('unpin') : t('pin')}
                            title={log.pinned ? t('unpin') : t('pin')}
                            className={`p-1 rounded transition-colors ${
                              log.pinned
                                ? 'text-[var(--pin-accent)] hover:bg-[var(--bg-elevated)]'
                                : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
                            }`}
                          >
                            <Pin className="w-3.5 h-3.5" />
                          </button>
                        </td>

                        <td className="py-2.5 px-3 align-middle">
                          <button
                            type="button"
                            onClick={() => log.category_id && onFilterCategory(log.category_id)}
                            className="inline-flex items-center gap-2 text-xs font-medium text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors max-w-[130px]"
                            title={log.category_name || t('uncategorized')}
                          >
                            <span
                              className="w-2 h-2 rounded-full shrink-0"
                              style={{ backgroundColor: log.category_color || '#64748b' }}
                            />
                            <span className="truncate">{log.category_name || t('uncategorized')}</span>
                          </button>
                        </td>

                        <td className="py-2.5 px-3 align-middle max-w-[520px]">
                          <button
                            type="button"
                            onClick={() => onViewDetail(log)}
                            dir="auto"
                            className="w-full text-start text-sm text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors truncate block"
                            title={log.message}
                          >
                            {log.message}
                          </button>
                        </td>

                        <td className="py-2.5 px-3 align-middle">
                          {log.tags.length === 0 ? (
                            <span className="text-xs text-[var(--text-muted)]">—</span>
                          ) : (
                            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                              {log.tags.slice(0, 4).map((tag) => (
                                <button
                                  key={tag.id}
                                  type="button"
                                  onClick={() => onToggleTag(tag.name)}
                                  className="inline-flex items-center gap-1 text-xs font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                                  title={`#${tag.name}`}
                                >
                                  <span style={{ color: tag.color }}>#</span>
                                  <span>{tag.name}</span>
                                </button>
                              ))}
                              {log.tags.length > 4 && (
                                <span className="text-[11px] font-mono text-[var(--text-muted)]">
                                  +{log.tags.length - 4}
                                </span>
                              )}
                            </div>
                          )}
                        </td>

                        <td
                          className="py-2.5 px-3 align-middle text-end text-xs font-mono tabular-nums text-[var(--text-secondary)] whitespace-nowrap"
                          title={formatExactTime(log.created_at)}
                        >
                          {formatRelativeTime(log.created_at)}
                        </td>

                        <td className="py-2.5 ps-2 pe-4 align-middle text-end relative">
                          <button
                            type="button"
                            onClick={() => setOpenMenuId(isMenuOpen ? null : log.id)}
                            aria-label={t('colActions')}
                            className="p-1.5 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-colors"
                          >
                            <MoreVertical className="w-4 h-4" />
                          </button>

                          {isMenuOpen && (
                            <>
                              <div
                                className="fixed inset-0 z-20"
                                onClick={() => setOpenMenuId(null)}
                                aria-hidden="true"
                              />
                              <div className="absolute end-4 top-10 z-30 w-40 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] py-1 shadow-lg text-start">
                                <button
                                  type="button"
                                  onClick={() => {
                                    setOpenMenuId(null);
                                    onEditLog(log);
                                  }}
                                  className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                                >
                                  <Pencil className="w-3.5 h-3.5" />
                                  <span>{t('edit')}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setOpenMenuId(null);
                                    onTogglePin(log);
                                  }}
                                  className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                                >
                                  {log.pinned ? <PinOff className="w-3.5 h-3.5" /> : <Pin className="w-3.5 h-3.5" />}
                                  <span>{log.pinned ? t('unpin') : t('pin')}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setOpenMenuId(null);
                                    onCopyMessage(log.message);
                                  }}
                                  className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                                >
                                  <Copy className="w-3.5 h-3.5" />
                                  <span>{t('copyText')}</span>
                                </button>
                                <div className="my-1 border-t border-[var(--border-hairline)]" />
                                <button
                                  type="button"
                                  onClick={() => {
                                    setOpenMenuId(null);
                                    onDeleteLog(log);
                                  }}
                                  className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                  <span>{t('delete')}</span>
                                </button>
                              </div>
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile card layout */}
            <div className="md:hidden divide-y divide-[var(--border-hairline)]">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className={`p-4 space-y-2.5 ${log.pinned ? 'bg-[var(--pin-surface)]' : ''}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{ backgroundColor: log.category_color || '#64748b' }}
                      />
                      <span className="text-xs font-medium text-[var(--text-primary)] truncate">
                        {log.category_name || t('uncategorized')}
                      </span>
                      {log.pinned && (
                        <span className="text-[11px] font-medium text-[var(--pin-accent)] flex items-center gap-1">
                          <Pin className="w-3 h-3" />
                          <span>{t('pinned')}</span>
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono tabular-nums text-[var(--text-muted)] shrink-0">
                      {formatRelativeTime(log.created_at)}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => onViewDetail(log)}
                    dir="auto"
                    className="w-full text-start text-sm text-[var(--text-primary)] line-clamp-3 leading-relaxed"
                  >
                    {log.message}
                  </button>

                  {log.tags.length > 0 && (
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                      {log.tags.map((tag) => (
                        <button
                          key={tag.id}
                          type="button"
                          dir="ltr"
                          onClick={() => onToggleTag(tag.name)}
                          className="text-xs font-mono text-[var(--text-secondary)]"
                        >
                          <span style={{ color: tag.color }}>#</span>
                          {tag.name}
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="pt-1 flex items-center justify-end text-xs text-[var(--text-secondary)]">
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => onTogglePin(log)}
                        aria-label={log.pinned ? t('unpin') : t('pin')}
                        className="p-1.5 rounded hover:bg-[var(--bg-hover)]"
                      >
                        <Pin className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => onEditLog(log)}
                        aria-label={t('edit')}
                        className="p-1.5 rounded hover:bg-[var(--bg-hover)]"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => onDeleteLog(log)}
                        aria-label={t('delete')}
                        className="p-1.5 rounded text-red-400 hover:bg-red-500/10"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Pagination */}
        <div className="px-4 py-3 border-t border-[var(--border-hairline)] flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)]">
          <div>
            {t('showing')} <span className="font-mono tabular-nums text-[var(--text-primary)]">{startIdx}</span> {t('to')}{' '}
            <span className="font-mono tabular-nums text-[var(--text-primary)]">{endIdx}</span> {t('of')}{' '}
            <span className="font-mono tabular-nums text-[var(--text-primary)]">{totalLogs}</span> {t('logsWord')}
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)] disabled:opacity-40 transition-colors"
            >
              {lang === 'fa' ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
              <span>{t('prev')}</span>
            </button>

            <div className="hidden sm:flex items-center gap-1">
              {renderPageNumbers().map((p, idx) =>
                p === '...' ? (
                  <span key={`e-${idx}`} className="px-2 text-[var(--text-muted)]">
                    …
                  </span>
                ) : (
                  <button
                    key={p}
                    type="button"
                    onClick={() => onPageChange(p)}
                    className={`min-w-[28px] h-7 px-2 rounded-md font-mono tabular-nums transition-colors ${
                      p === page
                        ? 'bg-[var(--accent)] text-white font-medium'
                        : 'border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)]'
                    }`}
                  >
                    {p}
                  </button>
                )
              )}
            </div>

            <button
              type="button"
              disabled={page >= totalPages || totalLogs === 0}
              onClick={() => onPageChange(page + 1)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)] disabled:opacity-40 transition-colors"
            >
              <span>{t('next')}</span>
              {lang === 'fa' ? <ChevronLeft className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="page-size-select">{t('perPage')}</label>
            <select
              id="page-size-select"
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="px-2 py-1 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-primary)] font-mono tabular-nums"
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};

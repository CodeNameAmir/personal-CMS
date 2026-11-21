import React, { useState } from 'react';
import { getTranslator } from '../i18n/translations';
import type { Language, LogStats } from '../types/logbook';

interface StatsViewProps {
  lang: Language;
  stats: LogStats | null;
  loading: boolean;
  onFilterCategory: (categoryId: string) => void;
  onFilterTag: (tagName: string) => void;
}

export const StatsView: React.FC<StatsViewProps> = ({
  lang,
  stats,
  loading,
  onFilterCategory,
  onFilterTag,
}) => {
  const t = getTranslator(lang);
  const [hoveredDay, setHoveredDay] = useState<{ day: string; count: number } | null>(null);

  if (loading && !stats) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-24 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] animate-pulse"
          />
        ))}
      </div>
    );
  }

  if (!stats) return null;

  const maxDayCount = Math.max(1, ...stats.by_day.map((d) => d.count));
  const maxCatCount = Math.max(1, ...stats.by_category.map((c) => c.count));
  const maxTagCount = Math.max(1, ...stats.by_tag.map((tg) => tg.count));

  return (
    <div className="space-y-6">
      {/* KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="text-xs font-medium text-[var(--text-secondary)]">{t('totalLogs')}</div>
          <div className="mt-2 text-3xl font-semibold font-mono tabular-nums text-[var(--text-primary)]">
            {stats.total_logs}
          </div>
          <div className="mt-1 text-xs text-[var(--text-muted)] font-mono tabular-nums">
            {stats.with_attachments} {t('withAttachmentsCount')}
          </div>
        </div>

        <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="text-xs font-medium text-[var(--text-secondary)]">{t('pinnedLogs')}</div>
          <div className="mt-2 text-3xl font-semibold font-mono tabular-nums text-[var(--pin-accent)]">
            {stats.pinned_logs}
          </div>
          <div className="mt-1 text-xs text-[var(--text-muted)]">{t('keptAtTop')}</div>
        </div>

        <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="text-xs font-medium text-[var(--text-secondary)]">{t('categories')}</div>
          <div className="mt-2 text-3xl font-semibold font-mono tabular-nums text-[var(--text-primary)]">
            {stats.total_categories}
          </div>
          <div className="mt-1 text-xs text-[var(--text-muted)]">{t('activeWorkspaces')}</div>
        </div>

        <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="text-xs font-medium text-[var(--text-secondary)]">{t('activeTags')}</div>
          <div className="mt-2 text-3xl font-semibold font-mono tabular-nums text-[var(--text-primary)]">
            {stats.total_tags}
          </div>
          <div className="mt-1 text-xs text-[var(--text-muted)]">{t('uniqueLabels')}</div>
        </div>
      </div>

      {/* Asymmetric 2-column chart row: 30-day activity + Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* 30-day activity bar chart */}
        <div className="lg:col-span-7 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                {t('activity30Days')}
              </h2>
              <p className="text-xs text-[var(--text-muted)]">{t('dailyVolume')}</p>
            </div>
            {hoveredDay && (
              <div className="text-xs font-mono tabular-nums text-[var(--text-primary)]">
                {hoveredDay.day}: <span className="font-semibold">{hoveredDay.count}</span>
              </div>
            )}
          </div>

          <div dir="ltr" className="h-52 flex items-end gap-1 pt-4 border-b border-[var(--border-hairline)]">
            {stats.by_day.map((d) => {
              const heightPct = d.count === 0 ? 4 : Math.max(10, Math.round((d.count / maxDayCount) * 100));
              const isHovered = hoveredDay?.day === d.day;
              return (
                <button
                  key={d.day}
                  type="button"
                  onMouseEnter={() => setHoveredDay(d)}
                  onMouseLeave={() => setHoveredDay(null)}
                  onFocus={() => setHoveredDay(d)}
                  aria-label={`${d.day}: ${d.count} logs`}
                  className="flex-1 h-full flex items-end group focus:outline-none"
                >
                  <span
                    className={`w-full rounded-t transition-colors ${
                      d.count === 0
                        ? 'bg-[var(--bg-elevated)]'
                        : isHovered
                          ? 'bg-[var(--accent)]'
                          : 'bg-[var(--accent)]/65 group-hover:bg-[var(--accent)]'
                    }`}
                    style={{ height: `${heightPct}%` }}
                  />
                </button>
              );
            })}
          </div>
          <div dir="ltr" className="mt-2 flex items-center justify-between text-[11px] font-mono tabular-nums text-[var(--text-muted)]">
            <span>{stats.by_day[0]?.day || ''}</span>
            <span>{stats.by_day[Math.floor(stats.by_day.length / 2)]?.day || ''}</span>
            <span>{stats.by_day[stats.by_day.length - 1]?.day || ''}</span>
          </div>
        </div>

        {/* Category breakdown */}
        <div className="lg:col-span-5 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">{t('logsByCategory')}</h2>
            <p className="text-xs text-[var(--text-muted)]">{t('clickCatFilter')}</p>
          </div>
          {stats.by_category.length === 0 ? (
            <div className="py-12 text-center text-xs text-[var(--text-muted)]">
              {t('noCategorizedLogs')}
            </div>
          ) : (
            <div className="space-y-3">
              {stats.by_category.map((cat) => {
                const widthPct = Math.max(4, Math.round((cat.count / maxCatCount) * 100));
                const sharePct =
                  stats.total_logs > 0 ? Math.round((cat.count / stats.total_logs) * 100) : 0;
                return (
                  <button
                    key={cat.category_id}
                    type="button"
                    onClick={() => onFilterCategory(cat.category_id)}
                    className="w-full text-start group"
                  >
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="flex items-center gap-2 font-medium text-[var(--text-primary)] group-hover:text-[var(--accent)] transition-colors">
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ backgroundColor: cat.category_color }}
                        />
                        <span className="truncate">{cat.category_name}</span>
                      </span>
                      <span className="font-mono tabular-nums text-[var(--text-secondary)]">
                        {cat.count} <span className="text-[var(--text-muted)]">({sharePct}%)</span>
                      </span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${widthPct}%`, backgroundColor: cat.category_color }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Top Tags Breakdown */}
      <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
        <div className="mb-4">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">{t('tagDistribution')}</h2>
          <p className="text-xs text-[var(--text-muted)]">{t('mostUsedTags')}</p>
        </div>
        {stats.by_tag.length === 0 ? (
          <div className="py-8 text-center text-xs text-[var(--text-muted)]">
            {t('noTagsAssigned')}
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-4">
            {stats.by_tag.slice(0, 12).map((tag) => {
              const widthPct = Math.max(6, Math.round((tag.count / maxTagCount) * 100));
              return (
                <button
                  key={tag.tag_id}
                  type="button"
                  onClick={() => onFilterTag(tag.tag_name)}
                  className="py-1.5 text-start group transition-colors"
                >
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span dir="ltr" className="font-mono font-medium text-[var(--text-primary)] group-hover:text-[var(--accent)] truncate transition-colors">
                      <span style={{ color: tag.tag_color }}>#</span>
                      {tag.tag_name}
                    </span>
                    <span className="font-mono tabular-nums text-[var(--text-secondary)]">
                      {tag.count}
                    </span>
                  </div>
                  <div className="h-1 w-full rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${widthPct}%`, backgroundColor: tag.tag_color }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

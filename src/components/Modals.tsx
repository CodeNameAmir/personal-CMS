import React, { useEffect, useState } from 'react';
import {
  Check,
  Copy,
  FileUp,
  Hash,
  KeyRound,
  Pencil,
  Pin,
  PinOff,
  Send,
  Trash2,
  Webhook,
  X,
} from 'lucide-react';
import {
  createApiToken,
  deleteApiToken,
  getLoadedConfig,
  listApiTokens,
  sendWebhookLog,
} from '../api/client';
import { getTranslator } from '../i18n/translations';
import type {
  ApiTokenRecord,
  Category,
  CreatedApiToken,
  ImportResult,
  Language,
  LogEntry,
  Tag,
  ThemeId,
} from '../types/logbook';
import {
  CATEGORY_PALETTE,
  MAX_CATEGORY_NAME_LENGTH,
  MAX_LOG_MESSAGE_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_TAGS_PER_LOG,
  MIN_PASSWORD_LENGTH,
  TAG_PALETTE,
  formatExactTime,
  formatRelativeTime,
  isValidHexColor,
  parseTagInput,
  safeHexColor,
} from '../utils/logFormatters';

interface ModalShellProps {
  title: string;
  closeLabel: string;
  onClose: () => void;
  maxWidth?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

const ModalShell: React.FC<ModalShellProps> = ({
  title,
  closeLabel,
  onClose,
  maxWidth = 'max-w-lg',
  children,
  footer,
}) => {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div className="fixed inset-0" onClick={onClose} aria-hidden="true" />
      <div
        className={`relative z-10 w-full ${maxWidth} max-h-[90vh] flex flex-col rounded-xl border border-[var(--border-strong)] bg-[var(--bg-surface)] overflow-hidden`}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border-hairline)]">
          <h2 className="text-base font-semibold text-[var(--text-primary)]">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={closeLabel}
            className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 overflow-y-auto flex-1">{children}</div>
        {footer && (
          <div className="px-5 py-3.5 border-t border-[var(--border-hairline)] flex items-center justify-end gap-2 bg-[var(--bg-surface)]">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

/* ---------------- Log Editor Modal ---------------- */
interface LogEditorModalProps {
  lang: Language;
  log: LogEntry | null;
  categories: Category[];
  availableTags: Tag[];
  onClose: () => void;
  onSave: (payload: {
    id?: string;
    message: string;
    category_id: string | null;
    tags: string[];
    pinned: boolean;
  }) => Promise<void>;
}

export const LogEditorModal: React.FC<LogEditorModalProps> = ({
  lang,
  log,
  categories,
  availableTags,
  onClose,
  onSave,
}) => {
  const t = getTranslator(lang);
  const defaultCatId =
    log?.category_id ||
    categories.find((c) => c.name.toLowerCase() === 'general')?.id ||
    categories[0]?.id ||
    '';

  const [message, setMessage] = useState(log?.message || '');
  const [categoryId, setCategoryId] = useState(defaultCatId);
  const [selectedTags, setSelectedTags] = useState<string[]>(log ? log.tags.map((tg) => tg.name) : []);
  const [tagDraft, setTagDraft] = useState('');
  const [pinned, setPinned] = useState(Boolean(log?.pinned));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const addTagToken = (raw: string) => {
    const parsed = parseTagInput(raw);
    if (parsed.length === 0) return;
    setSelectedTags((prev) => Array.from(new Set([...prev, ...parsed])).slice(0, MAX_TAGS_PER_LOG));
    setTagDraft('');
  };

  const handleTagDraftChange = (value: string) => {
    if (value.includes(',') || value.includes('،')) {
      const normalized = value.replace(/،/g, ',');
      const parts = normalized.split(',');
      const trailing = parts.pop() || '';
      const completed = parseTagInput(parts.join(','));
      if (completed.length > 0) {
        setSelectedTags((prev) => Array.from(new Set([...prev, ...completed])).slice(0, MAX_TAGS_PER_LOG));
      }
      setTagDraft(trailing);
      return;
    }
    setTagDraft(value);
  };

  const handleTagKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      if (tagDraft.trim()) addTagToken(tagDraft);
    } else if (e.key === 'Backspace' && !tagDraft && selectedTags.length > 0) {
      setSelectedTags((prev) => prev.slice(0, -1));
    }
  };

  const draftNeedle = parseTagInput(tagDraft)[0] || '';
  const suggestedTags = availableTags.filter(
    (tg) => !selectedTags.includes(tg.name) && (!draftNeedle || tg.name.includes(draftNeedle))
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!message.trim()) {
      setError(t('logMessageRequired'));
      return;
    }

    const extra = tagDraft.trim() ? parseTagInput(tagDraft) : [];
    const finalTags = Array.from(new Set([...selectedTags, ...extra])).slice(0, MAX_TAGS_PER_LOG);

    setSaving(true);
    try {
      await onSave({
        id: log?.id,
        message: message.trim(),
        category_id: categoryId || null,
        tags: finalTags,
        pinned,
      });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save log');
    } finally {
      setSaving(false);
    }
  };

  return (
    <ModalShell
      title={log ? t('editLog') : t('newLog')}
      closeLabel={t('closeModal')}
      onClose={onClose}
      maxWidth="max-w-xl"
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)] transition-colors"
          >
            {t('cancel')}
          </button>
          <button
            type="submit"
            form="log-editor-form"
            disabled={saving}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-50 transition-colors"
          >
            {saving ? t('saving') : t('saveLog')}
          </button>
        </>
      }
    >
      <form id="log-editor-form" onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="log-msg-input" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {t('messageLabel')}
          </label>
          <textarea
            id="log-msg-input"
            dir="auto"
            rows={5}
            maxLength={MAX_LOG_MESSAGE_LENGTH}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder={t('messagePlaceholder')}
            className="w-full px-3.5 py-2.5 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] font-mono leading-relaxed"
            required
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="log-cat-select" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
              {t('categoryLabel')}
            </label>
            <select
              id="log-cat-select"
              value={categoryId}
              onChange={(e) => setCategoryId(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
            >
              <option value="">{t('uncategorized')}</option>
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-end pb-1">
            <label className="inline-flex items-center gap-2.5 cursor-pointer select-none text-sm text-[var(--text-primary)]">
              <input
                type="checkbox"
                checked={pinned}
                onChange={(e) => setPinned(e.target.checked)}
                className="w-4 h-4 rounded accent-[var(--pin-accent)]"
              />
              <Pin className="w-4 h-4 text-[var(--pin-accent)]" />
              <span>{t('pinToTop')}</span>
            </label>
          </div>
        </div>

        {/* Advanced Tag Editor */}
        <div>
          <label htmlFor="log-tag-input" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {t('tagsInputLabel')}
          </label>
          <div className="p-2 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] focus-within:border-[var(--accent)] flex flex-wrap items-center gap-1.5">
            {selectedTags.map((tagName) => (
              <span
                key={tagName}
                dir="ltr"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-hairline)] text-xs font-mono text-[var(--text-primary)]"
              >
                <span className="text-[var(--accent)]">#</span>
                <span>{tagName}</span>
                <button
                  type="button"
                  onClick={() => setSelectedTags((prev) => prev.filter((item) => item !== tagName))}
                  aria-label={`${t('remove')} ${tagName}`}
                  className="text-[var(--text-muted)] hover:text-[var(--text-primary)] ms-0.5"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            <input
              id="log-tag-input"
              type="text"
              value={tagDraft}
              onChange={(e) => handleTagDraftChange(e.target.value)}
              onKeyDown={handleTagKeyDown}
              placeholder={selectedTags.length === 0 ? t('tagsInputPlaceholder') : t('tagsAddMore')}
              className="flex-1 min-w-[120px] bg-transparent text-xs font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none px-1 py-0.5"
            />
          </div>

          {suggestedTags.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-[var(--text-muted)] me-1">{t('existingTags')}</span>
              {suggestedTags.slice(0, 10).map((tg) => (
                <button
                  key={tg.id}
                  type="button"
                  dir="ltr"
                  onClick={() => addTagToken(tg.name)}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)] text-[11px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                >
                  <span style={{ color: safeHexColor(tg.color) }}>#</span>
                  <span>{tg.name}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {error && (
          <div className="px-3 py-2 rounded-lg text-xs bg-red-500/10 border border-red-500/30 text-red-400">
            {error}
          </div>
        )}
      </form>
    </ModalShell>
  );
};

/* ---------------- Log Detail Modal ---------------- */
interface LogDetailModalProps {
  lang: Language;
  log: LogEntry;
  onClose: () => void;
  onEdit: (log: LogEntry) => void;
  onTogglePin: (log: LogEntry) => void;
  onDelete: (log: LogEntry) => void;
  onCopy: (text: string) => void;
  onFilterTag: (tagName: string) => void;
}

export const LogDetailModal: React.FC<LogDetailModalProps> = ({
  lang,
  log,
  onClose,
  onEdit,
  onTogglePin,
  onDelete,
  onCopy,
  onFilterTag,
}) => {
  const t = getTranslator(lang);

  return (
    <ModalShell
      title={t('logDetails')}
      closeLabel={t('closeModal')}
      onClose={onClose}
      maxWidth="max-w-2xl"
      footer={
        <div className="w-full flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => {
              onClose();
              onDelete(log);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>{t('delete')}</span>
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onCopy(log.message)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)]"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{t('copyText')}</span>
            </button>
            <button
              type="button"
              onClick={() => onTogglePin(log)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)]"
            >
              {log.pinned ? <PinOff className="w-3.5 h-3.5" /> : <Pin className="w-3.5 h-3.5" />}
              <span>{log.pinned ? t('unpin') : t('pin')}</span>
            </button>
            <button
              type="button"
              onClick={() => {
                onClose();
                onEdit(log);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)]"
            >
              <Pencil className="w-3.5 h-3.5" />
              <span>{t('edit')}</span>
            </button>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-[110px_1fr] gap-y-2.5 text-xs">
          <span className="text-[var(--text-muted)]">{t('colCategory')}</span>
          <span className="flex items-center gap-2 font-medium text-[var(--text-primary)]">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: safeHexColor(log.category_color) }}
            />
            <span>{log.category_name || t('uncategorized')}</span>
          </span>

          <span className="text-[var(--text-muted)]">{t('createdLabel')}</span>
          <span className="font-mono tabular-nums text-[var(--text-primary)]">
            {formatExactTime(log.created_at)}
          </span>

          <span className="text-[var(--text-muted)]">{t('statusLabel')}</span>
          <span className="text-[var(--text-primary)]">
            {log.pinned ? t('pinnedToTop') : t('standardEntry')}
          </span>

          <span className="text-[var(--text-muted)]">{t('colTags')}</span>
          <div className="flex flex-wrap gap-2">
            {log.tags.length === 0 ? (
              <span className="text-[var(--text-muted)]">{t('none')}</span>
            ) : (
              log.tags.map((tg) => (
                <button
                  key={tg.id}
                  type="button"
                  dir="ltr"
                  onClick={() => {
                    onFilterTag(tg.name);
                    onClose();
                  }}
                  className="font-mono text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  <span style={{ color: safeHexColor(tg.color) }}>#</span>
                  {tg.name}
                </button>
              ))
            )}
          </div>
        </div>

        <div
          dir="auto"
          className="p-4 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] font-mono text-sm leading-relaxed text-[var(--text-primary)] whitespace-pre-wrap break-words max-h-72 overflow-y-auto"
        >
          {log.message}
        </div>
      </div>
    </ModalShell>
  );
};

/* ---------------- Category / Tag Color Modal ---------------- */
interface TaxonomyModalProps {
  lang: Language;
  kind: 'category' | 'tag';
  item: Category | Tag | null;
  onClose: () => void;
  onSave: (name: string, color: string, id?: string) => Promise<void>;
  onDelete?: (id: string) => Promise<void>;
}

export const TaxonomyModal: React.FC<TaxonomyModalProps> = ({
  lang,
  kind,
  item,
  onClose,
  onSave,
  onDelete,
}) => {
  const t = getTranslator(lang);
  const palette = kind === 'category' ? CATEGORY_PALETTE : TAG_PALETTE;
  const [name, setName] = useState(item?.name || '');
  const [color, setColor] = useState(item?.color || palette[0]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) {
      setError(t('nameRequired'));
      return;
    }
    if (!isValidHexColor(color)) {
      setError(t('invalidHexColor'));
      return;
    }
    setSaving(true);
    try {
      await onSave(name.trim(), color.trim(), item?.id);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!item || !onDelete) return;
    setSaving(true);
    try {
      await onDelete(item.id);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
      setSaving(false);
    }
  };

  const modalTitle =
    kind === 'category'
      ? item
        ? t('editCategory')
        : t('newCategory')
      : item
        ? t('editTag')
        : t('newTag');

  return (
    <ModalShell
      title={modalTitle}
      closeLabel={t('closeModal')}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="w-full flex items-center justify-between">
          <div>
            {item && onDelete && (
              <button
                type="button"
                disabled={saving}
                onClick={handleDelete}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-red-500/30 text-red-400 hover:bg-red-500/10"
              >
                {t('delete')}
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)]"
            >
              {t('cancel')}
            </button>
            <button
              type="submit"
              form="taxonomy-form"
              disabled={saving}
              className="px-4 py-1.5 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-50"
            >
              {saving ? t('saving') : t('save')}
            </button>
          </div>
        </div>
      }
    >
      <form id="taxonomy-form" onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="tax-name" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {kind === 'category' ? t('categoryName') : t('tagName')}
          </label>
          <div className="relative">
            {kind === 'tag' && (
              <Hash className="w-3.5 h-3.5 absolute start-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            )}
            <input
              id="tax-name"
              type="text"
              maxLength={kind === 'category' ? MAX_CATEGORY_NAME_LENGTH : 32}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={kind === 'category' ? 'Deployment' : 'production'}
              className={`w-full py-2 pe-3 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] ${
                kind === 'tag' ? 'ps-8 font-mono' : 'ps-3'
              }`}
              required
            />
          </div>
        </div>

        <div>
          <span className="block text-xs font-medium text-[var(--text-secondary)] mb-2">{t('colorLabel')}</span>
          <div className="flex items-center gap-3 mb-3">
            <input
              type="color"
              aria-label={t('colorLabel')}
              value={safeHexColor(color, palette[0])}
              onChange={(e) => setColor(e.target.value)}
              className="w-10 h-9 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] cursor-pointer"
            />
            <input
              type="text"
              dir="ltr"
              aria-label="Hex color code"
              value={color}
              onChange={(e) => setColor(e.target.value)}
              maxLength={7}
              className="w-28 px-3 py-1.5 text-xs font-mono rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)]"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {palette.map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setColor(c)}
                aria-label={`Select color ${c}`}
                className={`w-6 h-6 rounded-full transition-transform ${
                  color.toLowerCase() === c.toLowerCase()
                    ? 'ring-2 ring-white ring-offset-2 ring-offset-[var(--bg-surface)] scale-110'
                    : ''
                }`}
                style={{ backgroundColor: c }}
              />
            ))}
          </div>
        </div>

        {error && (
          <div className="px-3 py-2 rounded-lg text-xs bg-red-500/10 border border-red-500/30 text-red-400">
            {error}
          </div>
        )}
      </form>
    </ModalShell>
  );
};

/* ---------------- Import Modal ---------------- */
interface ImportModalProps {
  lang: Language;
  initialFormat: 'json' | 'csv';
  onClose: () => void;
  onImport: (format: 'json' | 'csv', input: { file?: File; content?: string }) => Promise<ImportResult>;
}

export const ImportModal: React.FC<ImportModalProps> = ({
  lang,
  initialFormat,
  onClose,
  onImport,
}) => {
  const t = getTranslator(lang);
  const [format, setFormat] = useState<'json' | 'csv'>(initialFormat);
  const [file, setFile] = useState<File | null>(null);
  const [pasted, setPasted] = useState('');
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState('');

  const handleUpload = async () => {
    setError('');
    setResult(null);
    if (!file && !pasted.trim()) {
      setError(t('importEmptyError'));
      return;
    }
    setImporting(true);
    try {
      const res = await onImport(format, file ? { file } : { content: pasted });
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <ModalShell
      title={t('importLogs')}
      closeLabel={t('closeModal')}
      onClose={onClose}
      maxWidth="max-w-lg"
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:bg-[var(--bg-hover)]"
          >
            {t('close')}
          </button>
          <button
            type="button"
            disabled={importing}
            onClick={handleUpload}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-50"
          >
            <FileUp className="w-3.5 h-3.5" />
            <span>{importing ? t('importing') : t('importData')}</span>
          </button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <label htmlFor="import-format" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {t('formatLabel')}
          </label>
          <select
            id="import-format"
            value={format}
            onChange={(e) => setFormat(e.target.value as 'json' | 'csv')}
            className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)]"
          >
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
          </select>
        </div>

        <div>
          <label htmlFor="import-file" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {t('selectFileLabel')}
          </label>
          <input
            id="import-file"
            type="file"
            accept=".json,.csv,text/csv,application/json"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="w-full text-xs text-[var(--text-secondary)] file:me-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-[var(--border-hairline)] file:bg-[var(--bg-elevated)] file:text-xs file:font-medium file:text-[var(--text-primary)]"
          />
        </div>

        <div>
          <label htmlFor="import-paste" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
            {t('orPasteRaw')} {format.toUpperCase()}
          </label>
          <textarea
            id="import-paste"
            dir="ltr"
            rows={4}
            value={pasted}
            onChange={(e) => setPasted(e.target.value)}
            placeholder={
              format === 'json'
                ? '[{"message": "Deployed v2", "category": "Deployment", "tags": ["prod"], "pinned": true}]'
                : 'category,tags,pinned,message\nDeployment,prod;nginx,true,"Reloaded config"'
            }
            className="w-full px-3 py-2 text-xs font-mono rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)]"
          />
        </div>

        {error && (
          <div className="px-3 py-2 rounded-lg text-xs bg-red-500/10 border border-red-500/30 text-red-400">
            {error}
          </div>
        )}

        {result && (
          <div className="p-3.5 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">{t('importedLabel')}</span>
              <span className="font-mono tabular-nums text-emerald-400 font-semibold">
                {result.imported}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">{t('skippedLabel')}</span>
              <span className="font-mono tabular-nums text-amber-400 font-semibold">
                {result.skipped}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[var(--text-secondary)]">{t('failedLabel')}</span>
              <span className="font-mono tabular-nums text-red-400 font-semibold">
                {result.failed}
              </span>
            </div>
            {result.errors.length > 0 && (
              <div className="pt-2 border-t border-[var(--border-hairline)] text-[11px] text-[var(--text-muted)] max-h-24 overflow-y-auto space-y-1">
                {result.errors.map((err, i) => (
                  <div key={i}>{err}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </ModalShell>
  );
};

/* ---------------- Workspace Settings, Language & Webhook / API Tokens Modal ---------------- */
interface AccountModalProps {
  lang: Language;
  onChangeLang: (lang: Language) => void;
  username: string;
  theme: ThemeId;
  onChangeTheme: (theme: ThemeId) => void;
  onChangePassword: (currentPass: string, newPass: string) => Promise<void>;
  onWebhookSent: () => Promise<void> | void;
  onNotify: (message: string, kind?: 'ok' | 'error' | 'info') => void;
  supabaseSql?: string;
  onClose: () => void;
}

export const AccountModal: React.FC<AccountModalProps> = ({
  lang,
  onChangeLang,
  username,
  theme,
  onChangeTheme,
  onChangePassword,
  onWebhookSent,
  onNotify,
  supabaseSql,
  onClose,
}) => {
  const t = getTranslator(lang);
  const [activeTab, setActiveTab] = useState<'general' | 'webhooks'>('general');

  // Password form state
  const [currentPass, setCurrentPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [copiedSql, setCopiedSql] = useState(false);

  // API Tokens & Webhook state
  const [tokens, setTokens] = useState<ApiTokenRecord[]>([]);
  const [loadingTokens, setLoadingTokens] = useState(false);
  const [tokenName, setTokenName] = useState('');
  const [creatingToken, setCreatingToken] = useState(false);
  const [newlyCreatedToken, setNewlyCreatedToken] = useState<CreatedApiToken | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [testWebhookToken, setTestWebhookToken] = useState('');
  const [sendingTest, setSendingTest] = useState(false);
  const [webhookError, setWebhookError] = useState('');

  useEffect(() => {
    if (activeTab !== 'webhooks') return;
    setLoadingTokens(true);
    listApiTokens()
      .then(setTokens)
      .catch((error) => {
        setWebhookError(error instanceof Error ? error.message : 'Failed to load tokens');
      })
      .finally(() => setLoadingTokens(false));
  }, [activeTab]);

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg('');
    setErr('');
    if (newPass.length < MIN_PASSWORD_LENGTH) {
      setErr(t('passwordMinLength'));
      return;
    }
    if (newPass.length > MAX_PASSWORD_LENGTH) {
      setErr(t('passwordMaxLength'));
      return;
    }
    if (newPass !== confirmPass) {
      setErr(t('passwordMismatch'));
      return;
    }
    setSaving(true);
    try {
      await onChangePassword(currentPass, newPass);
      setMsg(t('passwordUpdated'));
      setCurrentPass('');
      setNewPass('');
      setConfirmPass('');
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setWebhookError('');
    if (!tokenName.trim()) {
      setWebhookError(t('tokenNameRequired'));
      return;
    }
    setCreatingToken(true);
    try {
      const created = await createApiToken(tokenName.trim());
      setNewlyCreatedToken(created);
      setTestWebhookToken(created.raw_token);
      setTokenName('');
      setTokens((prev) => [
        {
          id: created.id,
          name: created.name,
          token_prefix: created.token_prefix,
          last_used_at: created.last_used_at,
          created_at: created.created_at,
        },
        ...prev,
      ]);
    } catch (error) {
      setWebhookError(error instanceof Error ? error.message : 'Failed to create token');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleRevokeToken = async (id: string) => {
    setWebhookError('');
    try {
      await deleteApiToken(id);
      setTokens((prev) => prev.filter((item) => item.id !== id));
    } catch (error) {
      setWebhookError(error instanceof Error ? error.message : 'Failed to revoke token');
    }
  };

  const cfg = getLoadedConfig();
  const baseSupabaseUrl = cfg.supabaseUrl ? cfg.supabaseUrl.replace(/\/+$/, '') : 'https://YOUR_PROJECT.supabase.co';
  const pubKey = cfg.supabasePublishableKey || 'YOUR_SUPABASE_PUBLISHABLE_KEY';
  const originUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-app.example.com';
  const sampleTokenForCurl = newlyCreatedToken?.raw_token || 'lbk_YOUR_API_TOKEN';
  const curlSnippet = cfg.bffEnabled
    ? `curl -X POST "${originUrl}/api/webhook" \\
  -H "Authorization: Bearer ${sampleTokenForCurl}" \\
  -H "Content-Type: application/json" \\
  -d '{"message":"Deploy completed on node-1","category":"Deployment","tags":["prod","webhook"],"pinned":false}'`
    : `curl -X POST "${baseSupabaseUrl}/rest/v1/rpc/lb_ingest_webhook" \\
  -H "apikey: ${pubKey}" \\
  -H "Authorization: Bearer ${pubKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"p_raw_token":"${sampleTokenForCurl}","p_message":"Deploy completed on node-1","p_category":"Deployment","p_tags":["prod","webhook"],"p_pinned":false}'`;

  const handleSendTestWebhook = async () => {
    setWebhookError('');
    const raw = testWebhookToken.trim();
    if (!raw) {
      setWebhookError(t('generateFirstTokenHint'));
      return;
    }
    setSendingTest(true);
    try {
      await sendWebhookLog(raw, {
        message: t('testWebhookMsg'),
        category: 'Webhook',
        tags: ['webhook', 'test'],
        pinned: false,
      });
      await onWebhookSent();
      const updatedTokens = await listApiTokens();
      setTokens(updatedTokens);
      onNotify(t('testWebhookSent'), 'ok');
    } catch (error) {
      setWebhookError(error instanceof Error ? error.message : 'Webhook test failed');
    } finally {
      setSendingTest(false);
    }
  };

  return (
    <ModalShell
      title={t('settingsTitle')}
      closeLabel={t('closeModal')}
      onClose={onClose}
      maxWidth="max-w-xl"
    >
      <div className="space-y-5">
        {/* Settings tabs */}
        <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)]">
          <button
            type="button"
            onClick={() => setActiveTab('general')}
            className={`py-2 px-3 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'general'
                ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] border border-[var(--border-strong)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-transparent'
            }`}
          >
            {t('tabGeneral')}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('webhooks')}
            className={`inline-flex items-center justify-center gap-1.5 py-2 px-3 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'webhooks'
                ? 'bg-[var(--bg-elevated)] text-[var(--text-primary)] border border-[var(--border-strong)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-transparent'
            }`}
          >
            <Webhook className="w-3.5 h-3.5" />
            <span>{t('tabWebhooks')}</span>
          </button>
        </div>

        {activeTab === 'general' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between p-3.5 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-xs">
              <div>
                <div className="text-[var(--text-muted)]">{t('signedInAs')}</div>
                <div className="mt-0.5 text-sm font-medium text-[var(--text-primary)]">{username}</div>
              </div>
              <div className="text-end">
                <div className="text-[var(--text-muted)]">{t('storageLabel')}</div>
                <div className="mt-0.5 font-mono text-[var(--text-primary)]">
                  {t('supabasePostgresLabel')}
                </div>
              </div>
            </div>

            {/* Language switcher */}
            <div>
              <span className="block text-xs font-medium text-[var(--text-secondary)] mb-2">
                {t('languageLabel')}
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => onChangeLang('en')}
                  className={`px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
                    lang === 'en'
                      ? 'border-[var(--accent)] bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                      : 'border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  English (LTR)
                </button>
                <button
                  type="button"
                  onClick={() => onChangeLang('fa')}
                  className={`px-3 py-2 rounded-lg border text-xs font-medium transition-colors ${
                    lang === 'fa'
                      ? 'border-[var(--accent)] bg-[var(--bg-elevated)] text-[var(--text-primary)]'
                      : 'border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  فارسی (RTL)
                </button>
              </div>
            </div>

            {/* Theme */}
            <div>
              <span className="block text-xs font-medium text-[var(--text-secondary)] mb-2">
                {t('appearanceTheme')}
              </span>
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { id: 'dark', label: t('themeGraphite'), preview: '#0f1115' },
                    { id: 'midnight', label: t('themeMidnight'), preview: '#0f172a' },
                    { id: 'light', label: t('themeLight'), preview: '#f5f5f4' },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onChangeTheme(item.id)}
                    className={`p-2.5 rounded-lg border text-start transition-colors ${
                      theme === item.id
                        ? 'border-[var(--accent)] bg-[var(--bg-elevated)]'
                        : 'border-[var(--border-hairline)] bg-[var(--bg-canvas)] hover:border-[var(--border-strong)]'
                    }`}
                  >
                    <div
                      className="w-full h-5 rounded border border-[var(--border-hairline)] mb-1.5"
                      style={{ backgroundColor: item.preview }}
                    />
                    <div className="text-xs font-medium text-[var(--text-primary)]">{item.label}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Change Password */}
            <form onSubmit={handlePasswordSubmit} className="space-y-3 pt-4 border-t border-[var(--border-hairline)]">
              <h3 className="text-xs font-semibold text-[var(--text-primary)]">{t('changePassword')}</h3>
              <div>
                <label htmlFor="cp-cur" className="block text-xs text-[var(--text-secondary)] mb-1">
                  {t('currentPassword')}
                </label>
                <input
                  id="cp-cur"
                  type="password"
                  dir="ltr"
                  maxLength={MAX_PASSWORD_LENGTH}
                  value={currentPass}
                  onChange={(e) => setCurrentPass(e.target.value)}
                  required
                  className="w-full px-3 py-1.5 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)]"
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="cp-new" className="block text-xs text-[var(--text-secondary)] mb-1">
                    {t('newPassword')}
                  </label>
                  <input
                    id="cp-new"
                    type="password"
                    dir="ltr"
                    minLength={MIN_PASSWORD_LENGTH}
                    maxLength={MAX_PASSWORD_LENGTH}
                    value={newPass}
                    onChange={(e) => setNewPass(e.target.value)}
                    required
                    className="w-full px-3 py-1.5 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)]"
                  />
                </div>
                <div>
                  <label htmlFor="cp-conf" className="block text-xs text-[var(--text-secondary)] mb-1">
                    {t('confirmPassword')}
                  </label>
                  <input
                    id="cp-conf"
                    type="password"
                    dir="ltr"
                    minLength={MIN_PASSWORD_LENGTH}
                    maxLength={MAX_PASSWORD_LENGTH}
                    value={confirmPass}
                    onChange={(e) => setConfirmPass(e.target.value)}
                    required
                    className="w-full px-3 py-1.5 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)]"
                  />
                </div>
              </div>
              {err && <div className="text-xs text-red-400">{err}</div>}
              {msg && <div className="text-xs text-emerald-400">{msg}</div>}
              <button
                type="submit"
                disabled={saving}
                className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-strong)] hover:bg-[var(--bg-hover)]"
              >
                {saving ? t('updating') : t('updatePassword')}
              </button>
            </form>

            {supabaseSql && (
              <div className="pt-4 border-t border-[var(--border-hairline)] space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-[var(--text-primary)]">
                    {t('supabaseSqlHintTitle')}
                  </h3>
                  <button
                    type="button"
                    onClick={async () => {
                      await navigator.clipboard.writeText(supabaseSql);
                      setCopiedSql(true);
                      setTimeout(() => setCopiedSql(false), 2000);
                    }}
                    className="text-xs text-[var(--accent)] hover:underline"
                  >
                    {copiedSql ? t('copied') : t('copySqlSchema')}
                  </button>
                </div>
                <pre dir="ltr" className="p-3 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[11px] font-mono max-h-40 overflow-auto">
                  {supabaseSql}
                </pre>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-5">
            <div>
              <h3 className="text-xs font-semibold text-[var(--text-primary)]">{t('apiTokensTitle')}</h3>
              <p className="mt-1 text-xs text-[var(--text-secondary)] leading-relaxed">{t('apiTokensDesc')}</p>
            </div>

            {/* Create new token */}
            <form onSubmit={handleCreateToken} className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                maxLength={64}
                value={tokenName}
                onChange={(e) => setTokenName(e.target.value)}
                placeholder={t('tokenNamePlaceholder')}
                aria-label={t('tokenNamePlaceholder')}
                className="flex-1 px-3 py-2 text-xs rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              />
              <button
                type="submit"
                disabled={creatingToken}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-50 whitespace-nowrap"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>{creatingToken ? t('generating') : t('generateToken')}</span>
              </button>
            </form>

            {/* One-time raw token banner */}
            {newlyCreatedToken && (
              <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                <div className="text-xs font-medium text-emerald-400">{t('tokenCreatedNotice')}</div>
                <div className="flex items-center gap-2">
                  <code
                    dir="ltr"
                    className="flex-1 px-2.5 py-1.5 rounded bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-xs font-mono text-[var(--text-primary)] truncate"
                  >
                    {newlyCreatedToken.raw_token}
                  </code>
                  <button
                    type="button"
                    onClick={async () => {
                      await navigator.clipboard.writeText(newlyCreatedToken.raw_token);
                      setCopiedToken(true);
                      setTimeout(() => setCopiedToken(false), 2000);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded bg-[var(--bg-surface)] border border-[var(--border-strong)] text-xs font-medium hover:bg-[var(--bg-hover)] whitespace-nowrap"
                  >
                    {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedToken ? t('copied') : t('copyToken')}</span>
                  </button>
                </div>
              </div>
            )}

            {webhookError && (
              <div className="px-3 py-2 rounded-lg text-xs bg-red-500/10 border border-red-500/30 text-red-400">
                {webhookError}
              </div>
            )}

            {/* Active tokens list */}
            <div>
              <div className="text-xs font-medium text-[var(--text-secondary)] mb-2">{t('activeTokens')}</div>
              {loadingTokens ? (
                <div className="p-3 text-xs text-[var(--text-muted)]">{t('pleaseWait')}</div>
              ) : tokens.length === 0 ? (
                <div className="p-3.5 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-xs text-[var(--text-muted)]">
                  {t('noTokensYet')}
                </div>
              ) : (
                <div className="divide-y divide-[var(--border-hairline)] rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-canvas)] overflow-hidden">
                  {tokens.map((tok) => (
                    <div key={tok.id} className="px-3.5 py-2.5 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-medium text-[var(--text-primary)] truncate">
                            {tok.name}
                          </span>
                          <code dir="ltr" className="text-[11px] font-mono text-[var(--text-muted)]">
                            {tok.token_prefix}…
                          </code>
                        </div>
                        <div className="mt-0.5 text-[11px] text-[var(--text-muted)] font-mono">
                          {t('createdAt')}: {formatRelativeTime(tok.created_at)} · {t('lastUsed')}:{' '}
                          {tok.last_used_at ? formatRelativeTime(tok.last_used_at) : t('neverUsed')}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRevokeToken(tok.id)}
                        className="px-2.5 py-1 text-[11px] font-medium rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 whitespace-nowrap"
                      >
                        {t('revoke')}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Webhook cURL example & Test Send */}
            <div className="pt-4 border-t border-[var(--border-hairline)] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--text-primary)]">{t('webhookExample')}</span>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(curlSnippet);
                    setCopiedCurl(true);
                    setTimeout(() => setCopiedCurl(false), 2000);
                  }}
                  className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copiedCurl ? t('copied') : t('copyText')}</span>
                </button>
              </div>
              <pre
                dir="ltr"
                className="p-3 rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[11px] font-mono text-[var(--text-secondary)] overflow-x-auto leading-relaxed"
              >
                {curlSnippet}
              </pre>

              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  dir="ltr"
                  value={testWebhookToken}
                  onChange={(e) => setTestWebhookToken(e.target.value)}
                  placeholder={t('webhookTokenInputPlaceholder')}
                  aria-label="Webhook API token"
                  className="flex-1 px-3 py-2 text-xs font-mono rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                />
                <button
                  type="button"
                  disabled={sendingTest}
                  onClick={handleSendTestWebhook}
                  className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-[var(--border-strong)] bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] disabled:opacity-50 whitespace-nowrap"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{sendingTest ? t('sendingTest') : t('sendTestWebhook')}</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </ModalShell>
  );
};

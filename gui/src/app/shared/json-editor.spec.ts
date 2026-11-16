import { render, screen, waitFor } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { JsonEditor, MONACO_LOADER } from './json-editor';

// rg-json-editor (angular-gui.md §1, S08 A11y): Monaco in accessible mode, plain-text alternative.

function fakeMonaco() {
  let value = '';
  let listener: () => void = () => undefined;
  const editor = {
    getValue: () => value,
    setValue: (v: string) => {
      value = v;
    },
    onDidChangeModelContent: (l: () => void) => {
      listener = l;
    },
    updateOptions: vi.fn(),
    dispose: vi.fn(),
    type: (v: string) => {
      value = v;
      listener();
    },
  };
  const create = vi.fn((_host: HTMLElement, opts: { value: string }) => {
    value = opts.value;
    return editor;
  });
  return { monaco: { editor: { create, setTheme: vi.fn() } }, editor, create };
}

describe('rg-json-editor', () => {
  it('tc_gui_003_creates_monaco_in_accessible_mode_and_syncs_the_value', async () => {
    const fake = fakeMonaco();
    const { fixture } = await render(JsonEditor, {
      inputs: { label: 'Document (JSON)', value: '{"a":1}' },
      providers: [{ provide: MONACO_LOADER, useValue: () => Promise.resolve(fake.monaco) }],
    });
    await waitFor(() => expect(fake.create).toHaveBeenCalled());
    expect(fake.create.mock.calls[0][1]).toMatchObject({
      value: '{"a":1}',
      language: 'json',
      accessibilitySupport: 'on',
      ariaLabel: 'Document (JSON)',
    });
    fake.editor.type('{"a":2}');
    expect(fixture.componentInstance.value()).toBe('{"a":2}');
    expect(screen.getByText(/Ctrl\+M/)).toBeTruthy();
  });

  it('tc_gui_003_plain_text_alternative_is_a_labelled_textarea', async () => {
    const { fixture } = await render(JsonEditor, {
      inputs: { label: 'Document (JSON)', value: '{}' },
      providers: [{ provide: MONACO_LOADER, useValue: () => new Promise(() => undefined) }],
    });
    const toggle = screen.getByRole('button', { name: 'Plain text editor' });
    await userEvent.click(toggle);
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    const text = screen.getByRole('textbox', { name: 'Document (JSON)' });
    await userEvent.type(text, ' ');
    expect(fixture.componentInstance.value()).toBe('{} ');
  });

  it('tc_gui_003_falls_back_to_plain_text_when_monaco_fails', async () => {
    await render(JsonEditor, {
      inputs: { label: 'Validator' },
      providers: [{ provide: MONACO_LOADER, useValue: () => Promise.reject(new Error('chunk')) }],
    });
    expect(await screen.findByRole('textbox', { name: 'Validator' })).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('could not be loaded');
  });
});

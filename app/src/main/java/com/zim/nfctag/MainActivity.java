package com.zim.nfctag;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import com.zim.nfctag.core.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
  private static final int GREEN = 0xff176b58, INK = 0xff182f28, MUTED = 0xff576961;
  private EditText endpoint, key, oldKey;
  private Spinner mode, oldMode;
  private CheckBox resume, migrate, lock;
  private TextView status, details, nfcStatus;
  private Button write, verify, cancel, open;
  private ProgressBar progress;
  private NfcAdapter adapter;
  private SharedPreferences records;
  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private final AtomicBoolean busy = new AtomicBoolean();
  private final AtomicReference<Action> armed = new AtomicReference<>();
  private volatile IsoDep activeTag;
  private String verifiedURL;

  private static final class Action {
    final TagTemplate template;
    final byte[] master, oldMaster;
    final String mode, oldMode;
    final boolean write, resume, lock;

    Action(
        TagTemplate t, byte[] k, String m, boolean w, boolean r, byte[] old, String om, boolean l) {
      template = t;
      master = k;
      mode = m;
      write = w;
      resume = r;
      oldMaster = old;
      oldMode = om;
      lock = l;
    }

    String fingerprint(String uid) {
      byte[] base =
          Bytes.join(
              master,
              Bytes.ascii(
                  "|"
                      + uid
                      + "|"
                      + mode
                      + "|"
                      + template.endpoint
                      + (lock ? "|permanent-lock" : "")));
      return Bytes.hex(
          Crypto.sha256(
              oldMaster == null
                  ? base
                  : Bytes.join(base, Bytes.ascii("|migration|" + oldMode + "|"), oldMaster)));
    }

    void clear() {
      Arrays.fill(master, (byte) 0);
      if (oldMaster != null) Arrays.fill(oldMaster, (byte) 0);
    }
  }

  @Override
  public void onCreate(Bundle state) {
    super.onCreate(state);
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    records = getSharedPreferences("provisioning", MODE_PRIVATE);
    adapter = NfcAdapter.getDefaultAdapter(this);
    buildUI();
  }

  private int dp(int n) {
    return Math.round(n * getResources().getDisplayMetrics().density);
  }

  private TextView text(String content, int size, int color) {
    TextView t = new TextView(this);
    t.setText(content);
    t.setTextSize(size);
    t.setTextColor(color);
    t.setPadding(0, dp(5), 0, dp(5));
    return t;
  }

  private void title(LinearLayout box, String text) {
    TextView t = text(text, 20, INK);
    t.setTypeface(null, Typeface.BOLD);
    box.addView(t);
  }

  private LinearLayout card(LinearLayout parent) {
    LinearLayout box = new LinearLayout(this);
    box.setOrientation(LinearLayout.VERTICAL);
    box.setPadding(dp(18), dp(16), dp(18), dp(16));
    GradientDrawable bg = new GradientDrawable();
    bg.setColor(Color.WHITE);
    bg.setCornerRadius(dp(18));
    box.setBackground(bg);
    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
    p.setMargins(0, dp(12), 0, 0);
    parent.addView(box, p);
    return box;
  }

  private Button button(LinearLayout box, String label) {
    Button b = new Button(this);
    b.setText(label);
    b.setAllCaps(false);
    b.setTextColor(GREEN);
    box.addView(b, new LinearLayout.LayoutParams(-1, dp(52)));
    return b;
  }

  private EditText input(LinearLayout box, String label, String hint, int inputType) {
    box.addView(text(label, 14, MUTED));
    EditText e = new EditText(this);
    e.setHint(hint);
    e.setTextSize(16);
    e.setSingleLine(true);
    e.setInputType(inputType);
    e.setSaveEnabled(false);
    e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
    box.addView(e, new LinearLayout.LayoutParams(-1, dp(54)));
    return e;
  }

  private void buildUI() {
    ScrollView scroll = new ScrollView(this);
    scroll.setFillViewport(true);
    scroll.setBackgroundColor(0xfff4f7f5);
    LinearLayout page = new LinearLayout(this);
    page.setOrientation(LinearLayout.VERTICAL);
    page.setPadding(dp(20), dp(20), dp(20), dp(30));
    scroll.addView(page);
    scroll.setOnApplyWindowInsetsListener(
        (v, insets) -> {
          page.setPadding(
              dp(20),
              dp(20) + insets.getSystemWindowInsetTop(),
              dp(20),
              dp(30) + insets.getSystemWindowInsetBottom());
          return insets;
        });
    TextView brand = text("NFC Tag Writer", 30, INK);
    brand.setTypeface(null, Typeface.BOLD);
    page.addView(brand);
    page.addView(text("Secure setup for NTAG 424 DNA TagTamper • v1.1.0", 16, MUTED));
    nfcStatus = text("", 14, GREEN);
    page.addView(nfcStatus);
    LinearLayout config = card(page);
    title(config, "1. Connect to your backend");
    endpoint =
        input(
            config,
            "Backend URL",
            "https://your-domain.example/tagtt",
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
    endpoint.setText(records.getString("endpoint", ""));
    key =
        input(
            config,
            "Master key (hex)",
            "Enter your saved backend master key",
            InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    config.addView(
        text(
            "Your key stays in memory. It is never sent to the backend or saved in app"
                + " preferences.",
            13,
            MUTED));
    config.addView(text("Key derivation — must match the backend", 14, MUTED));
    mode = new Spinner(this);
    ArrayAdapter<String> choices =
        new ArrayAdapter<>(
            this, android.R.layout.simple_spinner_item, new String[] {"legacy", "standard"});
    choices.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    mode.setAdapter(choices);
    mode.setSelection(records.getString("mode", "legacy").equals("standard") ? 1 : 0);
    config.addView(mode, new LinearLayout.LayoutParams(-1, dp(48)));
    LinearLayout writing = card(page);
    title(writing, "2. Write a tag");
    migrate = new CheckBox(this);
    migrate.setText(R.string.rewrite_unlocked);
    writing.addView(migrate);
    oldKey =
        input(
            writing,
            "Old backend master key (hex)",
            "The master key used to configure this tag",
            InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    writing.addView(
        text(
            "Old key derivation — use legacy for the original NFC Developer App workflow. Keep the"
                + " old key until migration finishes.",
            13,
            MUTED));
    oldMode = new Spinner(this);
    ArrayAdapter<String> oldChoices =
        new ArrayAdapter<>(
            this, android.R.layout.simple_spinner_item, new String[] {"legacy", "standard"});
    oldChoices.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    oldMode.setAdapter(oldChoices);
    writing.addView(oldMode, new LinearLayout.LayoutParams(-1, dp(48)));
    writing.addView(
        text(
            "Keep the tamper loop closed and hold the tag against the phone until setup finishes.",
            15,
            MUTED));
    resume = new CheckBox(this);
    resume.setText(R.string.resume_setup);
    writing.addView(resume);
    lock = new CheckBox(this);
    lock.setText(R.string.permanent_lock);
    writing.addView(lock);
    writing.addView(
        text(
            "Irreversible: the URL, file settings and keys cannot be changed afterward, even with"
                + " your master key. Reading and backend verification still work. Leave unchecked"
                + " to keep the tag editable.",
            13,
            MUTED));
    write = button(writing, "Write tag");
    write.setOnClickListener(v -> prepare(true));
    cancel = button(writing, "Cancel waiting for tag");
    cancel.setEnabled(false);
    cancel.setOnClickListener(
        v -> {
          Action a = armed.getAndSet(null);
          if (a != null) a.clear();
          setControls(false);
          showStatus("Cancelled", false);
        });
    LinearLayout checking = card(page);
    title(checking, "3. Verify the result");
    checking.addView(
        text(
            "Remove the written tag, then tap it again to verify its signature and tamper status.",
            15,
            MUTED));
    verify = button(checking, "Verify tag");
    verify.setOnClickListener(v -> prepare(false));
    open = button(checking, "Open verified URL");
    open.setEnabled(false);
    open.setOnClickListener(
        v -> {
          if (verifiedURL != null)
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(verifiedURL)));
        });
    LinearLayout feedback = card(page);
    title(feedback, "Tag status");
    progress = new ProgressBar(this);
    progress.setVisibility(View.GONE);
    feedback.addView(progress);
    status = text("Ready for setup", 17, INK);
    feedback.addView(status);
    details = text("", 14, MUTED);
    details.setTextIsSelectable(true);
    feedback.addView(details);
    page.addView(
        text("AES provisioning • encrypted tamper status • local verification", 12, MUTED));
    setContentView(scroll);
  }

  @Override
  protected void onResume() {
    super.onResume();
    if (adapter == null) {
      nfcStatus.setText(R.string.no_nfc);
      write.setEnabled(false);
      verify.setEnabled(false);
      return;
    }
    if (!adapter.isEnabled()) {
      nfcStatus.setText(R.string.enable_nfc);
      return;
    }
    nfcStatus.setText(R.string.nfc_available);
    Bundle options = new Bundle();
    options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);
    adapter.enableReaderMode(
        this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, options);
  }

  @Override
  protected void onPause() {
    if (adapter != null) adapter.disableReaderMode(this);
    Action a = armed.getAndSet(null);
    if (a != null) a.clear();
    if (!busy.get()) setControls(false);
    super.onPause();
  }

  @Override
  protected void onDestroy() {
    worker.shutdown();
    IsoDep iso = activeTag;
    if (iso != null)
      try {
        iso.close();
      } catch (IOException ignored) {
      }
    super.onDestroy();
  }

  private void prepare(boolean writing) {
    if (adapter == null || !adapter.isEnabled()) {
      showStatus("Enable NFC in Android settings first.", true);
      return;
    }
    try {
      TagTemplate template = new TagTemplate(endpoint.getText().toString().trim());
      byte[] master = Bytes.hex(key.getText().toString().trim());
      if (master.length != 16 && master.length != 32)
        throw new IllegalArgumentException("Master key must contain 32 or 64 hex digits");
      if (writing && Arrays.equals(master, new byte[16]))
        throw new IllegalArgumentException("Use your nonzero backend master key");
      byte[] oldMaster = null;
      if (writing && migrate.isChecked()) {
        try {
          oldMaster = Bytes.hex(oldKey.getText().toString().trim());
          if (oldMaster.length != 16 && oldMaster.length != 32)
            throw new IllegalArgumentException("Old master key must contain 32 or 64 hex digits");
        } catch (IllegalArgumentException e) {
          Arrays.fill(master, (byte) 0);
          if (oldMaster != null) Arrays.fill(oldMaster, (byte) 0);
          throw e;
        }
      }
      Action action =
          new Action(
              template,
              master,
              mode.getSelectedItem().toString(),
              writing,
              resume.isChecked(),
              oldMaster,
              oldMode.getSelectedItem().toString(),
              writing && lock.isChecked());
      if (writing) {
        new AlertDialog.Builder(this)
            .setTitle(
                action.lock
                    ? "Write and permanently lock this tag?"
                    : action.resume ? "Resume this setup?" : "Rewrite this unlocked tag?")
            .setMessage(
                "This changes all five tag keys and permanently enables tamper detection. Keep the"
                    + " tamper loop closed. Save your master key before continuing; it is needed to"
                    + " manage the tag later."
                    + (action.oldMaster == null
                        ? ""
                        : "\n\n"
                            + "Migration replaces the existing URL and keys. It does not reset"
                            + " tamper history. Keep both master keys until setup completes.")
                    + (action.lock
                        ? "\n\n"
                            + "PERMANENT LOCK: This cannot be undone. You will lose the ability"
                            + " to change the URL, settings or keys, even with the master key."
                            + " Verify the destination URL carefully."
                        : "")
                    + "\n\nBackend: "
                    + template.endpoint
                    + "\nDerivation: "
                    + action.mode)
            .setPositiveButton(
                action.lock ? "Write and permanently lock" : "Ready — scan tag",
                (d, w) -> arm(action))
            .setNegativeButton("Cancel", (d, w) -> action.clear())
            .setOnCancelListener(d -> action.clear())
            .show();
      } else arm(action);
    } catch (IllegalArgumentException e) {
      showStatus(e.getMessage(), true);
    }
  }

  private void arm(Action action) {
    // Reader callbacks claim one immutable Action. Replacing an unclaimed action
    // clears its secrets without touching an operation already running on the worker.
    Action previous = armed.getAndSet(action);
    if (previous != null) previous.clear();
    verifiedURL = null;
    open.setEnabled(false);
    details.setText("");
    records
        .edit()
        .putString("endpoint", action.template.endpoint)
        .putString("mode", action.mode)
        .apply();
    setControls(true);
    showStatus(
        action.write
            ? "Hold a TagTamper tag against the phone to write it."
            : "Tap the tag to verify it.",
        false);
  }

  private void setControls(boolean waiting) {
    boolean enabled = !waiting && !busy.get();
    write.setEnabled(enabled && adapter != null);
    verify.setEnabled(enabled && adapter != null);
    endpoint.setEnabled(enabled);
    key.setEnabled(enabled);
    mode.setEnabled(enabled);
    resume.setEnabled(enabled);
    lock.setEnabled(enabled);
    migrate.setEnabled(enabled);
    oldKey.setEnabled(enabled);
    oldMode.setEnabled(enabled);
    cancel.setEnabled(waiting && !busy.get());
    progress.setVisibility(busy.get() ? View.VISIBLE : View.GONE);
  }

  private void showStatus(String message, boolean error) {
    status.setText(message);
    status.setTextColor(error ? 0xffa43c27 : INK);
  }

  @Override
  public void onTagDiscovered(Tag tag) {
    if (!busy.compareAndSet(false, true)) return;
    Action action = armed.getAndSet(null);
    if (action == null) {
      busy.set(false);
      return;
    }
    runOnUiThread(() -> setControls(true));
    try {
      worker.execute(
          () -> {
            IsoDep iso = IsoDep.get(tag);
            try {
              if (iso == null)
                throw new IOException("Use an NTAG 424 DNA TagTamper tag (ISO-DEP required).");
              activeTag = iso;
              iso.connect();
              iso.setTimeout(5000);
              TagSession session = new TagSession(iso::transceive);
              if (action.write) {
                Provisioner.Observer observer =
                    new Provisioner.Observer() {
                      public void progress(String message) {
                        runOnUiThread(() -> showStatus(message, false));
                      }

                      public void checkpoint(String uid, String stage) throws IOException {
                        if (!records
                            .edit()
                            .putString("record." + uid + ".fingerprint", action.fingerprint(uid))
                            .putString("record." + uid + ".stage", stage)
                            .putString("record." + uid + ".endpoint", action.template.endpoint)
                            .commit())
                          throw new IOException("Cannot save recovery record; write stopped.");
                      }
                    };
                session.selectApplication();
                String found = Bytes.hex(session.version());
                String stage = records.getString("record." + found + ".stage", "");
                boolean pendingLock =
                    stage.equals("Permanent lock started")
                        || stage.equals("Discarding management key")
                        || stage.equals("Permanently locked");
                String uid;
                if (pendingLock) {
                  if (!action.lock
                      || !action.resume
                      || !records
                          .getString("record." + found + ".fingerprint", "")
                          .equals(action.fingerprint(found)))
                    throw new IOException(
                        "Permanent lock was started for this tag. Keep the same settings and select"
                            + " permanent lock plus Resume. If the management key was already"
                            + " discarded, use Verify; rewriting is impossible.");
                  uid = found;
                } else
                  uid =
                      Provisioner.write(
                          session,
                          action.template,
                          action.master,
                          action.mode,
                          action.oldMaster,
                          action.oldMode,
                          action.resume,
                          id ->
                              records
                                  .getString("record." + id + ".fingerprint", "")
                                  .equals(action.fingerprint(id)),
                          observer);
                if (action.lock) {
                  observer.progress("Verifying URL and signature before permanent lock…");
                  String dynamic = session.readDynamicURL();
                  if (!dynamic.startsWith(action.template.endpoint + "?"))
                    throw new IOException("Lock stopped: tag points to a different URL");
                  SunVerifier.Result checked =
                      SunVerifier.verify(dynamic, action.master, action.mode);
                  if (!checked.uid.equals(uid))
                    throw new IOException("Lock stopped: verified UID mismatch");
                  byte[] management = Crypto.derive(action.master, Bytes.hex(uid), 0, action.mode);
                  try {
                    TagLocker.lock(session, management, Bytes.hex(uid), observer);
                  } finally {
                    Arrays.fill(management, (byte) 0);
                  }
                  runOnUiThread(
                      () ->
                          showStatus(
                              "Written and permanently locked. Remove the tag, then tap Verify.",
                              false));
                }
                runOnUiThread(() -> details.setText(getString(R.string.written_details, uid)));
              } else {
                String dynamic = session.readDynamicURL();
                if (!dynamic.startsWith(action.template.endpoint + "?"))
                  throw new IOException("Tag points to a different backend URL.");
                SunVerifier.Result result = SunVerifier.verify(dynamic, action.master, action.mode);
                runOnUiThread(
                    () -> {
                      showStatus("Signature verified", false);
                      details.setText(
                          getString(
                              R.string.verified_details,
                              result.uid,
                              result.counter,
                              result.status));
                      verifiedURL = dynamic;
                      open.setEnabled(true);
                    });
              }
            } catch (Exception e) {
              String message =
                  e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
              runOnUiThread(
                  () -> {
                    showStatus("Setup stopped: " + message, true);
                    details.setText(
                        action.write
                            ? (action.lock
                                    ? "Permanent locking may have partly or fully completed. Keep"
                                        + " all settings, select Resume and the same lock option."
                                        + " Once the management key is discarded, rewriting and"
                                        + " lock recovery are impossible; Verify still checks the"
                                        + " tag signature. Verification alone does not prove the"
                                        + " lock completed. "
                                    : "")
                                + "If writing began, keep the same URL, master key and derivation"
                                + " mode, including the old master and mode for migration. Select"
                                + " Resume an interrupted setup and tap the same tag. A failed"
                                + " operation may already have reached the tag."
                            : "Confirm that the URL, master key and derivation mode match the"
                                + " backend and tag.");
                  });
            } finally {
              if (iso != null)
                try {
                  iso.close();
                } catch (IOException ignored) {
                }
              activeTag = null;
              action.clear();
              busy.set(false);
              runOnUiThread(() -> setControls(false));
            }
          });
    } catch (RejectedExecutionException e) {
      action.clear();
      busy.set(false);
    }
  }
}

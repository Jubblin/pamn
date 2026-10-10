// Save via the native Save dialog in Tauri (the dialog grants the fs plugin write access to the chosen path);
// plain browser dev falls back to an <a download>.
export async function download(name: string, text: string, type: string) {
  if ("__TAURI_INTERNALS__" in window) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({ defaultPath: name });
    if (path) await (await import("@tauri-apps/plugin-fs")).writeTextFile(path, text);
    return;
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

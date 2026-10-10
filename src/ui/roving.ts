import type { KeyboardEvent } from "react";

/** Arrow/Home/End navigation for role=tab / role=radio groups; moving focus also selects. Put on the container. */
export function rovingKeys(e: KeyboardEvent<HTMLElement>) {
  if (!["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End"].includes(e.key)) return;
  const items = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"],[role="radio"]')).filter((b) => !b.disabled);
  const i = items.indexOf(document.activeElement as HTMLButtonElement);
  if (i < 0) return;
  e.preventDefault();
  const fwd = e.key === "ArrowRight" || e.key === "ArrowDown";
  const n = e.key === "Home" ? 0 : e.key === "End" ? items.length - 1 : (i + (fwd ? 1 : -1) + items.length) % items.length;
  items[n].focus();
  items[n].click();
}

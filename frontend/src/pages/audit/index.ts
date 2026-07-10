import "../../lib/theme.css";
import { mount } from "svelte";
import AuditPage from "./AuditPage.svelte";

export default mount(AuditPage, {
  target: document.getElementById("app-root")!,
});

import "../../lib/theme.css";
import { mount } from "svelte";
import SetPasswordPage from "./SetPasswordPage.svelte";

export default mount(SetPasswordPage, {
  target: document.getElementById("app-root")!,
});

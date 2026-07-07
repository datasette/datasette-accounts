import "../../lib/theme.css";
import { mount } from "svelte";
import LoginAttemptsPage from "./LoginAttemptsPage.svelte";

export default mount(LoginAttemptsPage, {
  target: document.getElementById("app-root")!,
});

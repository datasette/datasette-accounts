import "../../lib/theme.css";
import { mount } from "svelte";
import RegisterPage from "./RegisterPage.svelte";

export default mount(RegisterPage, {
  target: document.getElementById("app-root")!,
});

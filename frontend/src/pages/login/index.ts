import { mount } from "svelte";
import LoginPage from "./LoginPage.svelte";

export default mount(LoginPage, {
  target: document.getElementById("app-root")!,
});

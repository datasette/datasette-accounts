import { mount } from "svelte";
import AccountPage from "./AccountPage.svelte";

export default mount(AccountPage, {
  target: document.getElementById("app-root")!,
});

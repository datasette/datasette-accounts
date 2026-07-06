import { mount } from "svelte";
import AdminPage from "./AdminPage.svelte";

export default mount(AdminPage, {
  target: document.getElementById("app-root")!,
});

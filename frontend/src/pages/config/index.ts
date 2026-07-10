import "../../lib/theme.css";
import { mount } from "svelte";
import ConfigPage from "./ConfigPage.svelte";

export default mount(ConfigPage, {
  target: document.getElementById("app-root")!,
});

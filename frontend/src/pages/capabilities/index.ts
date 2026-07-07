import "../../lib/theme.css";
import { mount } from "svelte";
import CapabilitiesPage from "./CapabilitiesPage.svelte";

export default mount(CapabilitiesPage, {
  target: document.getElementById("app-root")!,
});

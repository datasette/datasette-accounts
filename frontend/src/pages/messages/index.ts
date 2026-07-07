import "../../lib/theme.css";
import { mount } from "svelte";
import MessagesPage from "./MessagesPage.svelte";

export default mount(MessagesPage, {
  target: document.getElementById("app-root")!,
});

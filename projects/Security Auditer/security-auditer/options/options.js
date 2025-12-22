const defaults = { dom: true, storage: true, network: true };
(async () => {
  const cfg = Object.assign({}, defaults, await chrome.storage.local.get(Object.keys(defaults)));
  optDom.checked = cfg.dom; optStorage.checked = cfg.storage; optNetwork.checked = cfg.network;
  save.onclick = async () => {
    await chrome.storage.local.set({ dom: optDom.checked, storage: optStorage.checked, network: optNetwork.checked });
    save.textContent = 'Saved'; setTimeout(() => save.textContent = 'Save', 1200);
  };
})();

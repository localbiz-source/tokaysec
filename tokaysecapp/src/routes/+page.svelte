<script>
    import Button from "../stories/Button.svelte";
    import "../app.css";
    import ArrowIcon from "../stories/ArrowIcon.svelte";
    import ButtonGroup from "../stories/ButtonGroup.svelte";
    import AddPersonIcon from "../stories/AddPersonIcon.svelte";
    /*
 <header class="flex w-full flex-col px-5 pt-5">
          <div class="flex w-full flex-row items-center justify-between">
            <h3 class="font-['Myriad-Pro'] text-xl">Create Secret</h3>
          </div>
          <p class="text-md flex flex-row items-center justify-start gap-1.5 font-['Myriad-Pro']">This secret will be created under the <span class="rounded-full border border-emerald-500 bg-emerald-500/40 px-2 text-emerald-700">Default</span> project</p>
        </header>
        <div class="flex w-full flex-col gap-3 px-5">
          <div class="flex w-full flex-col gap-2">
            <label class="text-md font-['Myriad-Pro']">Name</label>
            <div class="w-full px-0.5">
              <input class="w-full border-1 border-neutral-200 bg-neutral-200 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-200 transition-all duration-150 hover:outline-neutral-500 focus:border-black focus:bg-white focus:outline-black" />
            </div>
          </div>
          <div class="flex w-full flex-col gap-2">
            <label class="text-md font-['Myriad-Pro']">Description (Optional)</label>
            <div class="w-full px-0.5">
              <textarea class="w-full border-1 border-neutral-200 bg-neutral-200 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-200 transition-all duration-150 hover:outline-neutral-500 focus:border-black focus:bg-white focus:outline-black"></textarea>
            </div>
          </div>
          <div class="flex w-full flex-col gap-2">
            <label class="text-md font-['Myriad-Pro']">Type</label>
            <div class="relative flex w-full flex-row px-0.5">
              <select class="w-full appearance-none border-1 border-neutral-200 bg-neutral-200 px-2 py-1.5 font-['Myriad-Pro'] text-sm outline-[1.5px] outline-neutral-200 transition-all duration-150 hover:outline-neutral-500 focus:border-black focus:bg-white focus:outline-black">
                <option>--</option>
                <option>API Key</option>
                <option>Dynamic Secret</option>
              </select>
              <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-500">
                <!-- Down arrow icon (Heroicons or SVG) -->
                <svg class="h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>
          </div>
    */
</script>

<div class="flex flex-col gap-5">
    <ButtonGroup members={[
        { style: "ghost", label: "Login", partOfButtonGroup: false },
        { style: "primary", label: "Create Account", icon: AddPersonIcon, partOfButtonGroup: false  },
    ]}/>
    <ButtonGroup
        members={[
            { style: "primary", label: "Create", icon: ArrowIcon },
            { style: "ghost", label: "Cancel" },
        ]}
    />
</div>

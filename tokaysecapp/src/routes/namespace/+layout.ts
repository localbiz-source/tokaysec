import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ params }) => {
  const { namespaceId, projectId } = params;

  // You could fetch dashboard metadata here too.
  return {
    namespaceId, projectId
  };
};
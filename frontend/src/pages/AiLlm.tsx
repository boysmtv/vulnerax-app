import EntityListPage from '../components/EntityListPage'

export default function AiLlm() {
  return (
    <EntityListPage
      title="AI / LLM Security"
      subtitle="LLM Models, Prompts, Data Poisoning, Output Validation"
      apiPath="/api/v1/ai-assets"
      columns={[
        { key: 'name', label: 'Model' },
        { key: 'type', label: 'Type' },
        { key: 'provider', label: 'Provider' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Model name', type: 'LLM/Embedding/RAG', provider: 'OpenAI/Anthropic/Local' }}
    />
  )
}

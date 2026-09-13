import EntityListPage from '../components/EntityListPage'

export default function Cicd() {
  return (
    <EntityListPage
      title="CI/CD Pipeline"
      subtitle="GitHub Actions, GitLab CI, Jenkins — Pipeline Security & Secrets"
      apiPath="/api/v1/cicd"
      columns={[
        { key: 'name', label: 'Pipeline' },
        { key: 'platform', label: 'Platform' },
        { key: 'status', label: 'Status' },
        { key: 'repository', label: 'Repository' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Pipeline name', platform: 'GITHUB_ACTIONS/GITLAB_CI/JENKINS', repository: 'org/repo' }}
    />
  )
}
